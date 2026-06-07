from fastapi.responses import HTMLResponse


async def index():
    """Endpoint for the UI of the API server.

    Returns:
        HTMLResponse:
        Returns the HTML content for the UI.
    """
    data = """
    <html>
        <head>
            <title>Vault API</title>
        </head>
        <body>
            <h1>Welcome to Vault API</h1>
            <p>Use the endpoints to interact with the vault.</p>
        </body>
    </html>
    """
    return HTMLResponse(content=data, status_code=200)
