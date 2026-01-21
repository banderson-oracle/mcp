"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

import os
from logging import Logger

import oci
from mcp.server.fastmcp import FastMCP

from . import __project__, __version__

logger = Logger(__name__, level="INFO")

mcp = FastMCP(
    name=__project__,
    instructions="This server provides tools to interact with the OCI Load Balancer resources. It includes tools to help with managing load balancers.",
)


def get_load_balancer_client():
    logger.info("entering get_load_balancer_client")
    config = oci.config.from_file(
        profile_name=os.getenv("OCI_CONFIG_PROFILE", oci.config.DEFAULT_PROFILE)
    )
    user_agent_name = __project__.split("oracle.", 1)[1].split("-server", 1)[0]
    config["additional_user_agent"] = f"{user_agent_name}/{__version__}"
    private_key = oci.signer.load_private_key_from_file(config["key_file"])
    token_file = config["security_token_file"]
    token = None
    with open(token_file, "r") as f:
        token = f.read()
    signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
    # Update this line to return the correct client
    return oci.load_balancer.LoadBalancerClient(config, signer=signer)


@mcp.tool(
    name="list_load_balancers",
    description="Lists the load balancers from the given compartment",
)
async def list_load_balancers(
    query: str,
) -> str:
    """Example tool implementation.

    Replace this with your own tool implementation.
    """
    project_name = "oracle load-balancer MCP Server"
    return f"Hello from {project_name}! Your query was {query}. Replace this with your tool's logic"


def main():
    """Run the MCP server with CLI argument support."""
    mcp.run()


if __name__ == "__main__":
    main()
