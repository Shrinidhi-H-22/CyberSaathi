
from flask import Blueprint, jsonify, render_template, request

from app.services.message_analyzer import (
    MAX_MESSAGE_LENGTH,
    analyze_message
)

from app.services.url_analyzer import (
    MAX_URL_LENGTH,
    analyze_url
)


# Create the main website blueprint
main_bp = Blueprint("main", __name__)


# Homepage route
@main_bp.route("/")
def home():
    return render_template("index.html")


# Message analysis API
@main_bp.route("/api/analyze-message", methods=["POST"])
def analyze_message_api():

    if not request.is_json:
        return jsonify({
            "error": "Please send the message as JSON."
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request."
        }), 400

    message = data.get("message")

    if not isinstance(message, str):
        return jsonify({
            "error": "Please provide a valid text message."
        }), 400

    if not message.strip():
        return jsonify({
            "error": "Please enter a message to analyze."
        }), 400

    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({
            "error": (
                f"Message cannot exceed "
                f"{MAX_MESSAGE_LENGTH} characters."
            )
        }), 400

    try:
        result = analyze_message(message)

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    return jsonify(result), 200


# URL analysis API
@main_bp.route("/api/analyze-url", methods=["POST"])
def analyze_url_api():

    if not request.is_json:
        return jsonify({
            "error": "Please send the URL as JSON."
        }), 415

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request."
        }), 400

    url = data.get("url")

    if not isinstance(url, str):
        return jsonify({
            "error": "Please provide a valid URL."
        }), 400

    if not url.strip():
        return jsonify({
            "error": "Please enter a URL to analyze."
        }), 400

    if len(url.strip()) > MAX_URL_LENGTH:
        return jsonify({
            "error": (
                f"URL cannot exceed "
                f"{MAX_URL_LENGTH} characters."
            )
        }), 400

    try:
        result = analyze_url(url)

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    return jsonify(result), 200
