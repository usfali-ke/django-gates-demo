"""Headers Django doesn't set itself."""

# The app uses no browser features, so all of the powerful ones are off.
PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"


class ExtraSecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("Permissions-Policy", PERMISSIONS_POLICY)
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Per-user pages must not be stored by shared caches or the browser.
        if request.user.is_authenticated and not request.path.startswith("/static/"):
            response["Cache-Control"] = "no-store"
        return response
