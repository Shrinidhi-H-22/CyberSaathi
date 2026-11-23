
import sqlite3

from flask import (
    Blueprint,
    current_app,
    jsonify,
    render_template,
    request
)

from app.services.history_service import (
    save_scan,
    get_recent_scans,
    clear_scan_history
)

from app.services.message_analyzer import (
    MAX_MESSAGE_LENGTH,
    analyze_message
)

from app.services.url_analyzer import (
    MAX_URL_LENGTH,
    analyze_url
)

from app.services.urlhaus_service import lookup_urlhaus


# Create the main website blueprint
main_bp = Blueprint("main", __name__)


def attach_history_status(scan_type, result):
    """
    Save scan metadata without interrupting a successful analysis
    if a temporary SQLite database error occurs.
    """

    try:
        history_id = save_scan(scan_type, result)

        result["history_id"] = history_id
        result["history_saved"] = True

    except sqlite3.Error:

        current_app.logger.exception(
            "Scan completed, but history could not be saved."
        )

        result["history_id"] = None
        result["history_saved"] = False

    return result


# Homepage route
@main_bp.route("/")
def home():
    return render_template("index.html")


# Scan history dashboard page
@main_bp.route("/history")
def history_page():
    return render_template("history.html")


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

    result = attach_history_status("message", result)

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

    # First perform the existing structural URL analysis.
    try:
        result = analyze_url(url)

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    # Then perform the additional URLhaus threat-intelligence lookup.
    # An external lookup failure must not interrupt structural analysis.
    try:
        urlhaus_result = lookup_urlhaus(url)

        if not isinstance(urlhaus_result, dict):
            urlhaus_result = {
                "status": "unavailable",
                "reason": "invalid_service_response"
            }

    except Exception:

        current_app.logger.exception(
            "URLhaus lookup failed. Structural analysis will continue."
        )

        urlhaus_result = {
            "status": "unavailable",
            "reason": "lookup_error"
        }

    # Add the external threat-intelligence result to the API response.
    result["urlhaus"] = urlhaus_result

    # Save only the existing non-sensitive scan metadata.
    result = attach_history_status("url", result)

    return jsonify(result), 200


# Scan history API
@main_bp.route("/api/history", methods=["GET"])
def scan_history_api():

    # Read optional history limit.
    limit_value = request.args.get("limit")

    if limit_value is None:
        limit = None

    else:
        try:
            limit = int(limit_value)

        except ValueError:
            return jsonify({
                "error": "History limit must be a valid number."
            }), 400

    try:
        scans = get_recent_scans(limit)

        return jsonify({
            "count": len(scans),
            "scans": scans
        }), 200

    except ValueError as error:
        return jsonify({
            "error": str(error)
        }), 400

    except sqlite3.Error:

        current_app.logger.exception(
            "Unable to retrieve scan history."
        )

        return jsonify({
            "error": "Unable to retrieve scan history."
        }), 500


# Clear scan history API
@main_bp.route("/api/history", methods=["DELETE"])
def delete_scan_history_api():

    try:

        deleted_count = clear_scan_history()

        return jsonify({
            "success": True,
            "deleted_count": deleted_count,
            "message": "Scan history cleared successfully."
        }), 200

    except sqlite3.Error:

        current_app.logger.exception(
            "Unable to clear scan history."
        )

        return jsonify({
            "error": "Unable to clear scan history."
        }), 500
