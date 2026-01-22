"""
Copyright (c) 2025, Oracle and/or its affiliates.
Licensed under the Universal Permissive License v1.0 as shown at
https://oss.oracle.com/licenses/upl.
"""

import os
from logging import Logger
from typing import Literal, Optional

import oci
from fastmcp import FastMCP
from oracle.oci_load_balancer_mcp_server.models import (
    # Backend,
    # BackendSet,
    # Listener,
    LoadBalancer,
    # map_backend,
    # map_backend_set,
    # map_listener,
    map_load_balancer,
)
from pydantic import Field

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


# @mcp.tool(
#     name="list_load_balancers",
#     description="Lists the load balancers from the given compartment",
# )
# async def list_load_balancers(
#     query: str,
# ) -> str:
#     """Example tool implementation.


#     Replace this with your own tool implementation.
#     """
#     project_name = "oracle load-balancer MCP Server"
#     return f"Hello from {project_name}! Your query was {query}. Replace this with your tool's logic"
@mcp.tool(
    name="list_load_balancers",
    description="Lists the load balancers from the given compartment",
)
def list_load_balancers(
    compartment_id: str = Field(..., description="The OCID of the compartment"),
    limit: Optional[int] = Field(
        None,
        description="The maximum amount of load balancers to return. If None, there is no limit.",
        ge=1,
    ),
    lifecycle_state: Optional[
        Literal[
            "CREATING",
            "UPDATING",
            "ACTIVE",
            "DELETING",
            "DELETED",
            "FAILED",
        ]
    ] = Field(
        None,
        description="The lifecycle state of the network load balancer to filter on",
    ),
) -> list[LoadBalancer]:
    nlbs: list[LoadBalancer] = []

    try:
        client = get_load_balancer_client()

        response: oci.response.Response = None
        has_next_page = True
        next_page: str = None

        while has_next_page and (limit is None or len(nlbs) < limit):
            kwargs = {
                "compartment_id": compartment_id,
                "page": next_page,
                "limit": limit,
            }

            if lifecycle_state is not None:
                kwargs["lifecycle_state"] = lifecycle_state

            response = client.list_network_load_balancers(**kwargs)
            has_next_page = response.has_next_page
            next_page = response.next_page if hasattr(response, "next_page") else None

            data: list[oci.network_load_balancer.models.NetworkLoadBalancer] = (
                response.data.items
            )
            for d in data:
                nlbs.append(map_network_load_balancer(d))

        logger.info(f"Found {len(nlbs)} Network Load Balancers")
        return nlbs

    except Exception as e:
        logger.error(f"Error in list_network_load_balancers tool: {str(e)}")
        raise e


def main():
    """Run the MCP server with CLI argument support."""
    mcp.run()


if __name__ == "__main__":
    main()
