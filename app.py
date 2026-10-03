from flask import Flask, jsonify, render_template, request
from analyzer import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB


@app.after_request
def secure_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze_route():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("code"), str):
        return jsonify(error="JSON me 'code' (string) chahiye."), 400
    try:
        return jsonify(analyze(data["code"]))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception:
        app.logger.exception("analysis failed")
        return jsonify(error="Internal error. Dobara try karo."), 500


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request bahut badi hai."), 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
