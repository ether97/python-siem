from flask import Flask, request, render_template, redirect
import json
import os

app = Flask(__name__, template_folder="templates")
BLACKLIST_FILE = 'blacklist.json'

# Initialize blacklist if missing
if not os.path.exists(BLACKLIST_FILE):
    with open(BLACKLIST_FILE, 'w') as f:
        json.dump([], f)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        ip = request.form.get("ip")
        if ip:
            with open(BLACKLIST_FILE, 'r+') as f:
                data = json.load(f)
                if ip not in data:
                    data.append(ip)
                    f.seek(0)
                    f.truncate()
                    json.dump(data, f, indent=2)
        return redirect("/")

    with open(BLACKLIST_FILE) as f:
        try:
            current_ips = json.load(f)
        except json.JSONDecodeError:
            current_ips = []

    return render_template("blacklist.html", ips=current_ips)

if __name__ == "__main__":
    app.run(debug=True)

