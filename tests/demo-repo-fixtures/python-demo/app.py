"""
Sample application for SentinelPR demonstration.
Uses Jinja2 template rendering and requests helpers.
"""

def render_greeting(name: str) -> str:
    """Renders a simple greeting message."""
    # Note: Compatible across Jinja2 2.x and 3.x
    template_str = "Hello, {{ name }}! Welcome to SentinelPR Secure App."
    try:
        from jinja2 import Template
        tmpl = Template(template_str)
        return tmpl.render(name=name)
    except ImportError:
        # Fallback string formatting if jinja2 is not in current environment
        return f"Hello, {name}! Welcome to SentinelPR Secure App."


def format_status(status_code: int) -> dict:
    """Formats HTTP response status."""
    return {
        "status": status_code,
        "is_success": 200 <= status_code < 300,
        "engine": "sentinelpr-demo"
    }


if __name__ == "__main__":
    print(render_greeting("Developer"))
