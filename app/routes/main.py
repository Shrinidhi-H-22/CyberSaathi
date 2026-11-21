
from flask import Blueprint, jsonify, render_template, request

from app.services.message_analyzer import (
    MAX_MESSAGE_LENGTH,
    analyze_message
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

    # Only accept JSON requests
    if not request.is_json:
        return jsonify({
            "error": "Please send the message as JSON."
        }), 415

    # Read the submitted JSON data
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Invalid JSON request."
        }), 400

    # Get the message
    message = data.get("message")

    if not isinstance(message, str):
        return jsonify({
            "error": "Please provide a valid text message."
        }), 400

    # Reject empty messages
    if not message.strip():
        return jsonify({
            "error": "Please enter a message to analyze."
        }), 400

    # Check the message length
    if len(message) > MAX_MESSAGE_LENGTH:
        return jsonify({
            "error": (
                f"Message cannot exceed "
                f"{MAX_MESSAGE_LENGTH} characters."
            )
        }), 400

    # Analyze the message
    try:
        result = analyze_message(message)

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    # Return the analysis result
    return jsonify(result), 200
