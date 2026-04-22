from flask import Flask, render_template, request, jsonify
import pickle
import os
from urllib.parse import urlparse
from feature import extract_features, rule_based_score
from integrity import verify_integrity, compare_hash, compute_sha256
from data import get_files_for_url, simulate_file_scan, get_redirects

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

MODEL_PATH = "model.pkl"
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError("model.pkl not found. Run model.py first.")

model = pickle.load(open(MODEL_PATH, "rb"))

url_history = []


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    return url


def analyze_url(url: str):
    """Hybrid ML + rule-based. Returns (is_phishing, confidence, reasons)."""
    url = normalize_url(url)
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None, None, ["Invalid URL — could not parse domain"]
    except Exception:
        return None, None, ["Invalid URL format"]

    features = extract_features(url)
    ml_proba = model.predict_proba([features])[0][1]
    rule_score, reasons = rule_based_score(url)

    hybrid = min((ml_proba * 100 * 0.6) + (rule_score * 0.4), 100.0)
    hybrid = round(hybrid, 1)
    return hybrid >= 40.0, hybrid, reasons


def risk_decision(url_confidence, url_result="safe", file_status=None, file_reason=None):
    """
    Combine URL risk + file integrity into final decision.

    Decision rules:
      URL phishing OR file tampered  → BLOCK  (HIGH)
      URL suspicious OR file unknown → WARN   (MEDIUM)
      URL safe AND file verified     → ALLOW  (LOW)

    Returns (risk_score, level, decision, decision_text, combined_reasons)
    """
    risk = url_confidence or 0
    combined_reasons = []

    # Adjust risk based on file integrity
    if file_status == "tampered":
        risk = min(risk + 40, 100)
        combined_reasons.append("🚨 File integrity mismatch detected — hash comparison failed")
    elif file_status == "verified":
        risk = max(risk - 10, 0)
        combined_reasons.append("✅ File authenticity verified — hash comparison passed")
    elif file_status == "unknown":
        risk = min(risk + 10, 100)
        if file_reason:
            combined_reasons.append(f"⚠️ {file_reason}")
        else:
            combined_reasons.append("⚠️ No expected hash provided — cannot confirm file authenticity")

    risk = round(risk, 1)

    # Force BLOCK if either signal is critical
    if url_result == "phishing" or file_status == "tampered":
        level    = "HIGH"
        decision = "block"
        decision_text = "🚨 Access Blocked — Phishing URL or tampered file detected."
    elif risk < 40:
        level    = "LOW"
        decision = "allow"
        decision_text = "✅ Access Allowed — No significant threats detected."
    elif risk < 70:
        level    = "MEDIUM"
        decision = "warn"
        decision_text = "⚠️ Proceed with Caution — Suspicious signals detected."
    else:
        level    = "HIGH"
        decision = "block"
        decision_text = "🚨 Access Blocked — High risk score detected."

    return risk, level, decision, decision_text, combined_reasons


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def home():
    ctx = dict(result=None, confidence=0, reasons=[], url_checked="",
               error="", history=url_history, risk_level=None,
               decision=None, decision_text=None, files=[],
               risk_score=0, redirects=[])

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        ctx["url_checked"] = url

        if not url:
            ctx["error"] = "Please enter a URL."
        else:
            is_phishing, confidence, reasons = analyze_url(url)
            if is_phishing is None:
                ctx["error"] = reasons[0]
            else:
                result = "phishing" if is_phishing else "safe"
                risk_score, risk_level, decision, decision_text, _ = risk_decision(
                    confidence, url_result=result
                )
                ctx.update(
                    result=result, confidence=confidence, reasons=reasons,
                    risk_level=risk_level, decision=decision,
                    decision_text=decision_text, risk_score=risk_score,
                    files=get_files_for_url(url, is_phishing),
                    redirects=get_redirects(url, is_phishing)
                )
                url_history.insert(0, dict(url=url, result=result,
                                           confidence=confidence, risk_level=risk_level))
                if len(url_history) > 10:
                    url_history.pop()

    return render_template("index.html", **ctx)


@app.route("/check_file", methods=["POST"])
def check_file():
    """
    Simulated file scan (from URL file list).
    Accepts optional user-provided expected hash for real comparison.
    Falls back to simulation if no hash given.
    """
    filename      = request.form.get("filename", "unknown_file")
    is_safe_str   = request.form.get("is_safe", "true")
    url_conf      = float(request.form.get("url_confidence", 0))
    url_result    = request.form.get("url_result", "safe")
    expected_hash = request.form.get("expected_hash", "").strip()

    is_safe = is_safe_str.lower() == "true"

    if expected_hash:
        # Real hash comparison using provided expected hash
        scan = simulate_file_scan(filename, is_safe)
        status, message, reason = compare_hash(scan["generated_hash"], expected_hash)
        scan["status"]  = status
        scan["message"] = message
    else:
        # Pure simulation — safe files verify, unsafe files tamper
        scan = simulate_file_scan(filename, is_safe)
        reason = (
            "File authenticity verified — hash comparison passed"
            if scan["status"] == "verified"
            else "File integrity mismatch detected — hash comparison failed"
        )

    risk_score, risk_level, decision, decision_text, combined_reasons = risk_decision(
        url_conf, url_result=url_result, file_status=scan["status"], file_reason=reason
    )

    return jsonify(
        filename       = filename,
        generated_hash = scan["generated_hash"],
        expected_hash  = scan["expected_hash"],
        status         = scan["status"],
        message        = scan["message"],
        reason         = reason,
        risk_score     = risk_score,
        risk_level     = risk_level,
        decision       = decision,
        decision_text  = decision_text,
        combined_reasons = combined_reasons,
    )


@app.route("/file-check", methods=["GET", "POST"])
def file_check():
    """Standalone real-file upload + SHA-256 integrity check with hash comparison."""
    ctx = dict(file_result=None, generated_hash=None, status=None,
               message=None, error=None, risk_level=None, decision=None,
               decision_text=None, filename=None, integrity_reason=None,
               combined_reasons=[], expected_hash_input="")

    if request.method == "POST":
        uploaded      = request.files.get("file")
        expected_hash = request.form.get("expected_hash", "").strip()
        ctx["expected_hash_input"] = expected_hash

        if not uploaded or uploaded.filename == "":
            ctx["error"] = "Please select a file to upload."
        else:
            try:
                ctx["filename"] = uploaded.filename
                gen_hash, status, message, reason = verify_integrity(
                    uploaded.stream, expected_hash or None
                )
                ctx.update(generated_hash=gen_hash, status=status,
                           message=message, file_result=status,
                           integrity_reason=reason)

                _, risk_level, decision, decision_text, combined_reasons = risk_decision(
                    0, url_result="safe", file_status=status, file_reason=reason
                )
                ctx.update(risk_level=risk_level, decision=decision,
                           decision_text=decision_text,
                           combined_reasons=combined_reasons)
            except Exception as e:
                ctx["error"] = f"Error processing file: {e}"

    return render_template("file.html", **ctx)


@app.route("/check", methods=["GET"])
def check_realtime():
    url = normalize_url(request.args.get("url", "").strip())
    if not url or len(url) < 5:
        return jsonify(prediction=None, confidence=0, reasons=[])
    is_phishing, confidence, reasons = analyze_url(url)
    if is_phishing is None:
        return jsonify(prediction=None, confidence=0, reasons=[])
    return jsonify(
        prediction="phishing" if is_phishing else "safe",
        confidence=confidence,
        reasons=reasons
    )


@app.route("/predict", methods=["POST"])
def predict_api():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify(error="Missing 'url' in request body"), 400
    url = data["url"].strip()
    is_phishing, confidence, reasons = analyze_url(url)
    if is_phishing is None:
        return jsonify(error=reasons[0]), 422
    _, risk_level, decision, decision_text, _ = risk_decision(
        confidence, url_result="phishing" if is_phishing else "safe"
    )
    return jsonify(
        url=url,
        prediction="phishing" if is_phishing else "safe",
        confidence=confidence,
        risk_level=risk_level,
        decision=decision,
        reasons=reasons
    )


if __name__ == "__main__":
    app.run(debug=True)
