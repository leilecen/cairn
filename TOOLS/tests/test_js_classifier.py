from utils.js_classifier import classification_priority, classify_js


def test_jquery_classified_as_third_party_library():
    result = classify_js("https://example.com/static/jquery.min.js", "")
    assert result.role == "third_party_library"
    assert result.suppression_status == "suppressed_third_party_library"


def test_login_js_classified_as_business_login():
    result = classify_js("https://example.com/js/login.js", "")
    assert result.role == "business_login"


def test_cryptojs_timestamp_nonce_classified_as_signature_or_crypto():
    result = classify_js(
        "https://example.com/js/sign.js",
        "const sign = CryptoJS.SHA256(timestamp + nonce); headers['X-Sign']=sign;",
    )
    assert result.role == "signature_or_crypto"


def test_captcha_keywords_classified_as_business_captcha():
    result = classify_js("https://example.com/js/app.js", "captcha smsCode verifyCode slider")
    assert result.role == "business_captcha"


def test_loan_keywords_classified_as_business_loan():
    result = classify_js("https://example.com/js/loan-center.js", "apply mortgage repay")
    assert result.role == "business_loan"


def test_template_asset_is_suppressed():
    result = classify_js("https://example.com/js/mod_<%= pkg.version%>.min.js", "")
    assert result.suppression_status == "suppressed_template_asset"


def test_classification_priority_prefers_business_over_third_party():
    assert classification_priority("business_login") > classification_priority("third_party_library")
