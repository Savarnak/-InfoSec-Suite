import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from feature import extract_features

# Expanded dataset — safe (0) and phishing (1)
data = [
    # --- SAFE ---
    ("https://google.com", 0),
    ("https://www.amazon.in/products", 0),
    ("https://github.com/user/repo", 0),
    ("https://stackoverflow.com/questions/12345", 0),
    ("https://openai.com/research", 0),
    ("https://wikipedia.org/wiki/Python", 0),
    ("https://linkedin.com/in/username", 0),
    ("https://microsoft.com/en-us/windows", 0),
    ("https://apple.com/iphone", 0),
    ("https://youtube.com/watch?v=abc123", 0),
    ("https://twitter.com/user", 0),
    ("https://reddit.com/r/programming", 0),
    ("https://netflix.com/browse", 0),
    ("https://spotify.com/us/home", 0),
    ("https://dropbox.com/home", 0),
    ("https://zoom.us/meeting", 0),
    ("https://slack.com/workspace", 0),
    ("https://notion.so/workspace", 0),
    ("https://trello.com/boards", 0),
    ("https://medium.com/@author/article", 0),
    ("https://dev.to/post/title", 0),
    ("https://npmjs.com/package/react", 0),
    ("https://pypi.org/project/flask", 0),
    ("https://docs.python.org/3/library", 0),
    ("https://flask.palletsprojects.com/en/2.0.x", 0),
    ("https://scikit-learn.org/stable/modules", 0),
    ("https://kaggle.com/datasets", 0),
    ("https://coursera.org/learn/machine-learning", 0),
    ("https://udemy.com/course/python", 0),
    ("https://aws.amazon.com/s3", 0),

    # --- PHISHING ---
    ("http://secure-login-paytm.xyz/verify", 1),
    ("http://verify-bank-account-alert.com/login", 1),
    ("http://free-money-now.biz/claim", 1),
    ("http://update-your-bank-info.net/secure", 1),
    ("http://login-secure-alert.xyz/account", 1),
    ("http://account-verification-required.com", 1),
    ("http://bank-login-update-alert.com/signin", 1),
    ("http://192.168.1.1/login/verify", 1),
    ("http://10.0.0.1/account/update", 1),
    ("http://paypal-secure-login.tk/verify", 1),
    ("http://amazon-account-suspended.ml/login", 1),
    ("http://bit.ly/3xFakeLink", 1),
    ("http://tinyurl.com/phishing-page", 1),
    ("http://ebay-login-verify-account.cf/signin", 1),
    ("http://support-apple-id-locked.ga/unlock", 1),
    ("http://secure.login.verify.bank.update.com/account", 1),
    ("http://www.paypal.com.secure-login.xyz/webscr", 1),
    ("http://signin-ebayisapi.dll.verify.com", 1),
    ("http://confirm-your-billing-info.net/update", 1),
    ("http://urgent-account-suspended-verify.com", 1),
    ("http://password-reset-required-now.xyz/reset", 1),
    ("http://validate-your-account-immediately.tk", 1),
    ("http://free-gift-card-claim-now.ml/win", 1),
    ("http://login-alert-suspicious-activity.cf", 1),
    ("http://secure-paypal-update-billing.gq/pay", 1),
    ("http://microsoft-support-alert-virus.xyz/fix", 1),
    ("http://apple-id-verify-locked-account.tk", 1),
    ("http://netflix-billing-update-required.ml", 1),
    ("http://amazon-prize-winner-claim.ga/prize", 1),
    ("http://bank-of-america-secure-login.cf/signin", 1),
]

urls = [d[0] for d in data]
labels = [d[1] for d in data]

X = [extract_features(url) for url in urls]
y = labels

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"✅ Model trained successfully!")
print(f"📊 Test Accuracy: {acc * 100:.2f}%")
print("\n📋 Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

with open("model.pkl", "wb") as f:
    pickle.dump(model, f)

print("💾 Model saved to model.pkl")
