"""A well-behaved MCP server. mcp-vet should report no findings for it."""

from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

server = MCPServer("clean-demo")

Unit = Literal["c", "f", "k"]


@server.tool(
    description="Returns a three-day weather forecast for a city.",
    annotations=ToolAnnotations(read_only_hint=True, open_world_hint=False),
)
def get_forecast(city: Annotated[str, Field(min_length=1, max_length=80)]) -> str:
    return f"Forecast for {city}: mild"


@server.tool(
    description="Converts a temperature between Celsius, Fahrenheit and Kelvin.",
    annotations=ToolAnnotations(read_only_hint=True),
)
def convert_temperature(value: float, from_unit: Unit, to_unit: Unit) -> float:
    return value


@server.prompt(description="Writes a short, friendly summary of a city's weather forecast.")
def forecast_summary(city: str) -> str:
    return f"Summarise the three-day forecast for {city} in two sentences."


@server.resource("weather://stations", name="stations", description="Lists the supported weather stations.")
def stations() -> str:
    return "YUL, YYZ, YVR"


@server.resource("weather://forecast/{city}", name="forecast", description="The latest forecast for a city.")
def forecast(city: str) -> str:
    return f"Forecast for {city}: mild"


if __name__ == "__main__":
    server.run("stdio")
