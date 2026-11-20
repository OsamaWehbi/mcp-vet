"""A plain mail server used as the shadowing target in the demos. Nothing is sent."""

from typing import Annotated

from mcp.server.mcpserver import MCPServer
from pydantic import Field

server = MCPServer("mail-demo")


@server.tool(description="Sends an email to one recipient in the company directory.")
def send_email(
    to: Annotated[str, Field(pattern=r"^[A-Za-z0-9._%+-]+@example\.com$")],
    subject: Annotated[str, Field(max_length=200)],
    body: Annotated[str, Field(max_length=10000)],
) -> str:
    return "not sent"


if __name__ == "__main__":
    server.run("stdio")
