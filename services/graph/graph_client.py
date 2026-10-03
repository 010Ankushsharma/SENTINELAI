"""Neo4j graph database client for attack path analysis."""
from neo4j import AsyncGraphDatabase
from shared.config import get_settings
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class GraphClient:
    def __init__(self):
        settings = get_settings()
        self._driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )

    async def close(self):
        await self._driver.close()

    async def initialize_schema(self):
        """Create indexes and constraints."""
        async with self._driver.session() as session:
            await session.run(
                "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE"
            )
            await session.run(
                "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.hostname IS UNIQUE"
            )
            await session.run(
                "CREATE CONSTRAINT IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE"
            )
            await session.run(
                "CREATE INDEX IF NOT EXISTS FOR (a:Alert) ON (a.alert_id)"
            )
            await session.run(
                "CREATE INDEX IF NOT EXISTS FOR (p:Process) ON (p.name)"
            )
        logger.info("Graph schema initialized")

    async def add_login_event(self, user: str, host: str, ip: str, success: bool):
        async with self._driver.session() as session:
            await session.run(
                """
                MERGE (u:User {name: $user})
                MERGE (h:Host {hostname: $host})
                MERGE (i:IP {address: $ip})
                MERGE (u)-[:LOGGED_IN_TO {success: $success, timestamp: datetime()}]->(h)
                MERGE (i)-[:CONNECTED_TO]->(h)
                """,
                user=user, host=host, ip=ip, success=success,
            )

    async def add_process_execution(self, host: str, process: str, command: str, user: str):
        async with self._driver.session() as session:
            await session.run(
                """
                MERGE (h:Host {hostname: $host})
                MERGE (p:Process {name: $process})
                MERGE (u:User {name: $user})
                MERGE (u)-[:EXECUTED {timestamp: datetime(), command: $command}]->(p)
                MERGE (p)-[:RAN_ON]->(h)
                """,
                host=host, process=process, command=command, user=user,
            )

    async def add_network_connection(self, src_ip: str, dst_ip: str, dst_port: int, domain: str = None):
        async with self._driver.session() as session:
            query = """
                MERGE (s:IP {address: $src_ip})
                MERGE (d:IP {address: $dst_ip})
                MERGE (s)-[:COMMUNICATED_WITH {port: $port, timestamp: datetime()}]->(d)
            """
            await session.run(query, src_ip=src_ip, dst_ip=dst_ip, port=dst_port)
            
            if domain:
                await session.run(
                    """
                    MERGE (d:Domain {name: $domain})
                    MERGE (i:IP {address: $dst_ip})
                    MERGE (i)-[:RESOLVES_TO]->(d)
                    """,
                    domain=domain, dst_ip=dst_ip,
                )

    async def add_alert(self, alert_id: str, rule_name: str, severity: str, related_entities: dict):
        async with self._driver.session() as session:
            await session.run(
                """
                MERGE (a:Alert {alert_id: $alert_id})
                SET a.rule_name = $rule_name, a.severity = $severity, a.timestamp = datetime()
                """,
                alert_id=alert_id, rule_name=rule_name, severity=severity,
            )
            if "user" in related_entities:
                await session.run(
                    """
                    MATCH (a:Alert {alert_id: $alert_id})
                    MERGE (u:User {name: $user})
                    MERGE (a)-[:INVOLVES]->(u)
                    """,
                    alert_id=alert_id, user=related_entities["user"],
                )
            if "ip" in related_entities:
                await session.run(
                    """
                    MATCH (a:Alert {alert_id: $alert_id})
                    MERGE (i:IP {address: $ip})
                    MERGE (a)-[:INVOLVES]->(i)
                    """,
                    alert_id=alert_id, ip=related_entities["ip"],
                )

    async def get_attack_path(self, entity_type: str, entity_value: str, depth: int = 5) -> list[dict]:
        """Reconstruct attack path from a starting entity."""
        async with self._driver.session() as session:
            result = await session.run(
                f"""
                MATCH path = (start:{entity_type} {{name: $value}})-[*1..{depth}]-(end)
                RETURN path
                LIMIT 50
                """,
                value=entity_value,
            )
            paths = []
            async for record in result:
                path = record["path"]
                paths.append({
                    "nodes": [dict(node) for node in path.nodes],
                    "relationships": [
                        {"type": rel.type, "properties": dict(rel)}
                        for rel in path.relationships
                    ],
                })
            return paths

    async def find_lateral_movement(self, user: str) -> list[dict]:
        """Find potential lateral movement by a user."""
        async with self._driver.session() as session:
            result = await session.run(
                """
                MATCH (u:User {name: $user})-[:LOGGED_IN_TO]->(h:Host)
                WITH u, collect(h) as hosts
                WHERE size(hosts) > 2
                RETURN u.name as user, [h in hosts | h.hostname] as hosts, size(hosts) as host_count
                """,
                user=user,
            )
            return [dict(record) async for record in result]
