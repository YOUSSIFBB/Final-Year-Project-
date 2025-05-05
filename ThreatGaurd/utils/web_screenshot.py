import requests


def get_screenshot_image(url):
    """
    Use Thum.io to get a screenshot image of a URL.
    Returns (image_bytes, None) on success or (None, error_message) on failure.
    No API key required.
    """
    try:
        # Generate screenshot URL (width 800px)
        api_url = f"https://image.thum.io/get/width/800/{url}"

        response = requests.get(api_url, timeout=15)
        if response.status_code == 200:
            return response.content, None
        else:
            return None, f"Thum.io Error {response.status_code}: {response.text}"
    except Exception as e:
        return None, f"Request failed: {str(e)}"
