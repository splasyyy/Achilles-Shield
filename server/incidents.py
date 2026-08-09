import os
import requests


def create_github_issue(title: str, body: str, labels=None) -> dict:
    """Create a GitHub issue in the configured repo using GITHUB_TOKEN and REPO_FULL_NAME env var.
    Returns the created issue JSON or {} on failure. This is opt-in; if no token or repo configured,
    the function returns without error.
    """
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("REPO_FULL_NAME")
    if not (token and repo):
        print("GitHub issue creation skipped: GITHUB_TOKEN or REPO_FULL_NAME not set")
        return {}

    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json"
    }
    payload = {"title": title, "body": body}
    if labels:
        payload["labels"] = labels
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=5)
        if r.status_code in (200, 201):
            return r.json()
        else:
            print(f"GitHub issue creation failed: {r.status_code} {r.text}")
            return {}
    except Exception as e:
        print(f"Error creating GitHub issue: {e}")
        return {}
