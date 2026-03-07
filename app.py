import json
import os
from datetime import date
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)

DATA_FILE = os.path.join(os.path.dirname(__file__), "data.json")
CONCENTRATIONS = [10, 20, 30, 40]


def load_data():
    if not os.path.exists(DATA_FILE):
        return {"inventory": [], "records": []}
    with open(DATA_FILE) as f:
        return json.load(f)


def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


@app.route("/")
def index():
    data = load_data()
    return render_template("index.html", inventory=data["inventory"], records=data["records"], concentrations=CONCENTRATIONS)


@app.route("/inventory/add", methods=["POST"])
def add_inventory():
    data = load_data()
    lot = request.form["lot_number"].strip()
    concentration = int(request.form["concentration"])
    quantity = int(request.form["quantity"])

    if not lot:
        return redirect(url_for("index"))

    # Check if this lot+concentration already exists
    for entry in data["inventory"]:
        if entry["lot_number"] == lot and entry["concentration"] == concentration:
            entry["quantity"] += quantity
            save_data(data)
            return redirect(url_for("index"))

    data["inventory"].append({
        "lot_number": lot,
        "concentration": concentration,
        "quantity": quantity,
        "date_received": str(date.today()),
    })
    save_data(data)
    return redirect(url_for("index"))


@app.route("/inventory/delete", methods=["POST"])
def delete_inventory():
    data = load_data()
    lot = request.form["lot_number"]
    concentration = int(request.form["concentration"])
    data["inventory"] = [
        e for e in data["inventory"]
        if not (e["lot_number"] == lot and e["concentration"] == concentration)
    ]
    save_data(data)
    return redirect(url_for("index"))


@app.route("/dispense", methods=["POST"])
def dispense():
    data = load_data()
    patient = request.form["patient_name"].strip()
    lot = request.form["lot_number"].strip()
    concentration = int(request.form["concentration"])
    quantity = int(request.form["quantity"])

    if not patient or not lot:
        return redirect(url_for("index"))

    # Deduct from inventory
    for entry in data["inventory"]:
        if entry["lot_number"] == lot and entry["concentration"] == concentration:
            entry["quantity"] = max(0, entry["quantity"] - quantity)
            break

    data["records"].append({
        "patient_name": patient,
        "lot_number": lot,
        "concentration": concentration,
        "quantity": quantity,
        "date": str(date.today()),
    })
    save_data(data)
    return redirect(url_for("index"))


@app.route("/patient/<path:name>")
def patient_lookup(name):
    data = load_data()
    records = [r for r in data["records"] if r["patient_name"].lower() == name.lower()]
    return jsonify(records)


@app.route("/record/delete", methods=["POST"])
def delete_record():
    data = load_data()
    idx = int(request.form["index"])
    if 0 <= idx < len(data["records"]):
        data["records"].pop(idx)
    save_data(data)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, port=5050)
