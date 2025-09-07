from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "Achilles Shield test server is running!"

if __name__ == "__main__":
    print(">>> Launching test server...")
    app.run(host="127.0.0.1", port=5000, debug=True)