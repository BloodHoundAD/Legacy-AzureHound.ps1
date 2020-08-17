from neo4j import GraphDatabase

db_url = "bolt://localhost:7687"
db_user = "neo4j"
db_pass = "neo4jj"

class DatabaseConnector(object):
    def __init__(self):
        super().__init__()
        self.driver = GraphDatabase.driver(
            db_url, auth=(db_user, db_pass))

    def run_query(self, statement: str, *args, **kwargs):
        with self.driver.session() as session:
            return session.run(statement, *args, **kwargs)

driver = DatabaseConnector()

print("[*] Set constraints")
try:
    driver.run_query('CREATE CONSTRAINT ON (azu:AZUser) ASSERT azu.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (g:Group) ASSERT g.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (g:User) ASSERT g.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azg:AZGroup) ASSERT azg.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azt:AZTenant) ASSERT azt.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azs:AZSubscription) ASSERT azs.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azrg:AZResourceGroup) ASSERT azrg.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azvm:AZVM) ASSERT azvm.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azkv:AZKeyVault) ASSERT azkv.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azd:AZDevice) ASSERT azd.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (azsp:AZServicePrincipal) ASSERT azsp.objectid IS UNIQUE')
except:
    pass
try:
    driver.run_query('CREATE CONSTRAINT ON (aza:AZApp) ASSERT aza.objectid IS UNIQUE')
except:
    pass

print("[*] Import external cloud users")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/users.csv" AS row
    WITH row
    WHERE row.OnPremisesSecurityIdentifier IS null AND row.TenantID IS null
    MERGE (u:AZUser {objectid: row.ObjectID})
    SET u.name = toUpper(row.UserPrincipalName)
""")
    
print("[*] Import cloud users that belong to a tenant")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/users.csv" AS row
    WITH row
    WHERE row.OnPremisesSecurityIdentifier IS null AND NOT row.TenantID IS null
    MERGE (u:AZUser {objectid: row.ObjectID})
    MERGE (azt:AZTenant {objectid:row.TenantID})
    MERGE (azt)-[:AZContains]->(u)
    SET u.name = toUpper(row.UserPrincipalName)
""")

print("[*] Import onprem users")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/users.csv" AS row
    WITH row
    WHERE NOT row.OnPremisesSecurityIdentifier IS null
    MERGE (u:User {objectid: row.OnPremisesSecurityIdentifier})
    SET u.name = toUpper(row.UserPrincipalName)
""")

print("[*] Import onprem groups")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/groups.csv" AS row
    WITH row
    WHERE NOT row.OnPremisesSecurityIdentifier IS null
    MERGE (g:Group {objectid: row.OnPremisesSecurityIdentifier})
    SET g.name = toUpper(row.DisplayName)
    SET g.azsyncid = row.ObjectId
""")

print("[*] Import cloud groups")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/groups.csv" AS row
    WITH row
    WHERE row.OnPremisesSecurityIdentifier IS null
    MERGE (azg:AZGroup {objectid: row.ObjectID})
    MERGE (azt:AZTenant {objectid:row.TenantID})
    MERGE (azt)-[:AZContains]->(azg)
    SET azg.name = toUpper(row.DisplayName)
""")

print("[*] Import tenants")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/tenants.csv" AS row
    MERGE (azt:AZTenant {objectid: row.ObjectId})
    SET azt.name = toUpper(row.DisplayName)
""")

print("[*] (AZTenant)-[AZContains]->(AZSubscription)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/subs.csv" AS row
    MERGE (azs:AZSubscription {objectid: row.SubscriptionId})
    SET azs.name = toUpper(row.Name)
    MERGE (azt:AZTenant {objectid: row.TenantId})
    MERGE (azt)-[:AZContains]->(azs)
""")

print("[*] (AZSubscription)-[AZContains]->(AZResourceGroup)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/resourcegroups.csv" AS row
    MERGE (azrg:AZResourceGroup {objectid: row.ResourceGroupID})
    SET azrg.name = toUpper(row.ResourceGroupName)
    MERGE (azs:AZSubscription {objectid: row.SubscriptionID})
    MERGE (azs)-[:AZContains]->(azrg)
""")

print("[*] (AZResourceGroup)-[AZContains]->(AZVM)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/vms.csv" AS row
    MERGE (azvm:AZVM {objectid: row.AZID})
    SET azvm.name = toUpper(row.AzVMName)
    MERGE (azrg:AZResourceGroup {objectid: row.ResourceGroupID})
    MERGE (azrg)-[:AZContains]->(azvm)
""")

print("[*] (AZResourceGroup)-[AZContains]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/keyvaults.csv" AS row
    MERGE (azkv:AZKeyVault {objectid: row.AzKeyVaultID})
    SET azkv.name = toUpper(row.AzKeyVaultName)
    MERGE (azrg:AZResourceGroup {objectid: row.ResourceGroupID})
    MERGE (azrg)-[:AZContains]->(azkv)
""")

print("[*] (AZUser)-[AZOwns]->(AZDevice)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/devices.csv" AS row
    WITH row
    WHERE row.OnPremisesSecurityIdentifier IS null AND NOT row.OwnerID IS null
    MERGE (azd:AZDevice {objectid: row.DeviceID})
    SET azd.name = toUpper(row.DeviceDisplayname)
    MERGE (azu:AZUser {objectid: row.OwnerID})
    MERGE (azu)-[:AZOwns]->(azd)
""")

print("[*] (User)-[AZOwns]->(AZDevice)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/devices.csv" AS row
    WITH row
    WHERE NOT row.OnPremisesSecurityIdentifier IS null AND NOT row.OwnerID IS null
    MERGE (azd:AZDevice {objectid: row.DeviceID})
    SET azd.name = toUpper(row.DeviceDisplayname)
    MERGE (u:User {objectid: row.OwnerOnPremID})
    MERGE (u)-[:AZOwns]->(azd)
""")

print("[*] (AZUser)-[AZOwns]->(AZGroup)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/groupowners.csv" AS row
    WITH row
    WHERE row.OwnerOnPremID IS null
    MERGE (azg:AZGroup {objectid: row.GroupID})
    SET azg.name = toUpper(row.GroupName)
    MERGE (azu:AZUser {objectid: row.OwnerID})
    MERGE (azu)-[:AZOwns]->(azg)
""")

print("[*] (User)-[AZOwns]->(AZGroup)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/groupowners.csv" AS row
    WITH row
    WHERE NOT row.OwnerOnPremID IS null
    MERGE (azg:AZGroup {objectid: row.GroupID})
    SET azg.name = toUpper(row.GroupName)
    MERGE (u:User {objectid: row.OwnerOnPremID})
    MERGE (u)-[:AZOwns]->(azg)
""")

print("[*] (n)-[MemberOf]->(AZGroup/Group)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/groupmembers.csv" AS row
    WITH row
    // (n)-[MemberOf]->(AZGroup)
    FOREACH(f in (CASE WHEN toUPPER(row.GroupOnPremID) IS null THEN [1] else [] END) |
      //(AZGroup)-[MemberOf]->(AZGroup)
      FOREACH(f in (CASE WHEN toUPPER(row.MemberOnPremID) IS null AND toUPPER(row.MemberType) IN ["GROUP"] THEN [1] else [] END) |
        MERGE (Group:AZGroup {objectid: row.GroupID})
        MERGE (Member:AZGroup {objectid: row.MemberID})
        MERGE (Member)-[r:MemberOf]->(Group)
    	SET Member.name = toUpper(row.MemberName)
      )
      //(AZUser)-[MemberOf]->(AZGroup)
      FOREACH(f in (CASE WHEN toUPPER(row.MemberOnPremID) IS null AND toUPPER(row.MemberType) IN ["USER"] THEN [1] else [] END) |
        MERGE (Group:AZGroup {objectid: row.GroupID})
        MERGE (Member:AZUser {objectid: row.MemberID})
        MERGE (Member)-[r:MemberOf]->(Group)
    	SET Member.name = toUpper(row.MemberName)
      )
      //(Group)-[MemberOf]->(AZGroup)
      FOREACH(f in (CASE WHEN NOT toUPPER(row.MemberOnPremID) IS null AND toUPPER(row.MemberType) IN ["GROUP"] THEN [1] else [] END) |
        MERGE (Group:AZGroup {objectid: row.GroupID})
        MERGE (Member:Group {objectid: row.MemberOnPremID})
        MERGE (Member)-[r:MemberOf]->(Group)
    	SET Member.name = toUpper(row.MemberName)
      )
      //(User)-[MemberOf]->(AZGroup)
      FOREACH(f in (CASE WHEN NOT toUPPER(row.MemberOnPremID) IS null AND toUPPER(row.MemberType) IN ["USER"] THEN [1] else [] END) |
        MERGE (Group:AZGroup {objectid: row.GroupID})
        MERGE (Member:User {objectid: row.MemberOnPremID})
        MERGE (Member)-[r:MemberOf]->(Group)
    	SET Member.name = toUpper(row.MemberName)
      )
    )
    // (n)-[MemberOf]->(Group)
    FOREACH(f in (CASE WHEN NOT toUPPER(row.GroupOnPremID) IS null THEN [1] else [] END) |
      //(Group)-[MemberOf]->(Group)
      FOREACH(f in (CASE WHEN NOT toUPPER(row.GroupOnPremID) IS null AND toUPPER(row.MemberType) IN ["GROUP"] THEN [1] else [] END) |
        MERGE (Group:Group {objectid: row.GroupOnPremID})
        MERGE (Member:Group {objectid: row.MemberOnPremID})
        MERGE (Member)-[r:MemberOf]->(Group)
    	SET Member.name = toUpper(row.MemberName)
      )
      //(User)-[MemberOf]->(Group)
      FOREACH(f in (CASE WHEN NOT toUPPER(row.GroupOnPremID) IS null AND toUPPER(row.MemberType) IN ["USER"] THEN [1] else [] END) |
        MERGE (Group:Group {objectid: row.GroupOnPremID})
        MERGE (Member:User {objectid: row.MemberOnPremID})
        MERGE (Member)-[r:MemberOf]->(Group)
    	SET Member.name = toUpper(row.MemberName)
      )
    )
""")

print("[*] ()-[]->(AZVM)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/vmpermissions.csv" AS row
    WITH row
    // (Azure Principal)-[]->(AZVM)
    FOREACH(f in (CASE WHEN toUPPER(row.ControllerOnPremID) IS null THEN [1] else [] END) |
      //(AZUser)-[]->(AZVM)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["USER"] THEN [1] else [] END) |
        // (AZUser)-[:AZOwns]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azu)-[:AZOwns]->(azvm)
    	)
        // (AZUser)-[:AZContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azu)-[:AZContributor]->(azvm)
    	)
    	// (AZUser)-[:AZVMContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["VIRTUAL MACHINE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azu)-[:AZVMContributor]->(azvm)
    	)
    	// (AZUser)-[:AZAvereContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["AVERE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azu)-[:AZAvereContributor]->(azvm)
    	)
    	// (AZUser)-[:AZUserAccessAdministrator]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azu)-[:AZUserAccessAdministrator]->(azvm)
    	)
      )
      //(AZGroup)-[]->(AZVM)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["GROUP"] THEN [1] else [] END) |
        // (AZGroup)-[:AZOwns]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azg)-[:AZOwns]->(azvm)
    	)
        // (AZGroup)-[:AZContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azg)-[:AZContributor]->(azvm)
    	)
    	// (AZGroup)-[:AZVMContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["VIRTUAL MACHINE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azg)-[:AZVMContributor]->(azvm)
    	)
    	// (AZGroup)-[:AZAvereContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["AVERE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azg)-[:AZAvereContributor]->(azvm)
    	)
    	// (AZGroup)-[:AZUserAccessAdministrator]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azg)-[:AZUserAccessAdministrator]->(azvm)
    	)
      )
      //(AZServicePrincipal)-[]->(AZVM)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["SERVICE PRINCIPAL"] THEN [1] else [] END) |
        // (AZServicePrincipal)-[:AZOwns]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azsp)-[:AZOwns]->(azvm)
    	)
        // (AZServicePrincipal)-[:AZContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azsp)-[:AZContributor]->(azvm)
    	)
    	// (AZServicePrincipal)-[:AZVMContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["VIRTUAL MACHINE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azsp)-[:AZVMContributor]->(azvm)
    	)
    	// (AZServicePrincipal)-[:AZAvereContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["AVERE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azsp)-[:AZAvereContributor]->(azvm)
    	)
    	// (AZServicePrincipal)-[:AZUserAccessAdministrator]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (azsp)-[:AZUserAccessAdministrator]->(azvm)
    	)
      )
    )
    // (On-prem Principal)-[]->(AZVM)
    FOREACH(f in (CASE WHEN NOT toUPPER(row.ControllerOnPremID) IS null THEN [1] else [] END) |
      //(User)-[]->(AZVM)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["USER"] THEN [1] else [] END) |
        // (User)-[:AZOwns]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (u)-[:AZOwns]->(azvm)
    	)
        // (User)-[:AZContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (u)-[:AZContributor]->(azvm)
    	)
    	// (User)-[:AZVMContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["VIRTUAL MACHINE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (u)-[:AZVMContributor]->(azvm)
    	)
    	// (User)-[:AZAvereContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["AVERE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (u)-[:AZAvereContributor]->(azvm)
    	)
    	// (User)-[:AZUserAccessAdministrator]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (u)-[:AZUserAccessAdministrator]->(azvm)
    	)
      )
      //(Group)-[]->(AZVM)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["GROUP"] THEN [1] else [] END) |
        // (Group)-[:AZOwns]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (g)-[:AZOwns]->(azvm)
    	)
        // (Group)-[:AZContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (g)-[:AZContributor]->(azvm)
    	)
    	// (Group)-[:AZVMContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["VIRTUAL MACHINE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (g)-[:AZVMContributor]->(azvm)
    	)
    	// (Group)-[:AZAvereContributor]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["AVERE CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (g)-[:AZAvereContributor]->(azvm)
    	)
    	// (Group)-[:AZUserAccessAdministrator]->(AZVM)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azvm:AZVM {objectid: row.VMID})
    	  MERGE (g)-[:AZUserAccessAdministrator]->(azvm)
    	)
      )
    )
""")

print("[*] ()-[]->(AZResourceGroup)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/rgpermissions.csv" AS row
    WITH row
    // (Azure Principal)-[]->(AZResourceGroup)
    FOREACH(f in (CASE WHEN toUPPER(row.ControllerOnPremID) IS null THEN [1] else [] END) |
      //(AZUser)-[]->(AZResourceGroup)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["USER"] THEN [1] else [] END) |
        // (AZUser)-[:AZOwns]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (azu)-[:AZOwns]->(azrg)
    	)
    	// (AZUser)-[:AZUserAccessAdministrator]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (azu)-[:AZUserAccessAdministrator]->(azrg)
    	)
      )
      //(AZGroup)-[]->(AZResourceGroup)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["GROUP"] THEN [1] else [] END) |
        // (AZGroup)-[:AZOwns]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (azg)-[:AZOwns]->(azrg)
    	)
    	// (AZGroup)-[:AZUserAccessAdministrator]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (azg)-[:AZUserAccessAdministrator]->(azrg)
    	)
      )
      //(AZServicePrincipal)-[]->(AZResourceGroup)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["SERVICE PRINCIPAL"] THEN [1] else [] END) |
        // (AZServicePrincipal)-[:AZOwns]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (azsp)-[:AZOwns]->(azrg)
    	)
    	// (AZServicePrincipal)-[:AZUserAccessAdministrator]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (azsp)-[:AZUserAccessAdministrator]->(azrg)
    	)
      )
    )
    // (On-prem Principal)-[]->(AZResourceGroup)
    FOREACH(f in (CASE WHEN NOT toUPPER(row.ControllerOnPremID) IS null THEN [1] else [] END) |
      //(User)-[]->(AZResourceGroup)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["USER"] THEN [1] else [] END) |
        // (User)-[:AZOwns]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (u)-[:AZOwns]->(azrg)
    	)
    	// (User)-[:AZUserAccessAdministrator]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (u)-[:AZUserAccessAdministrator]->(azrg)
    	)
      )
      //(Group)-[]->(AZResourceGroup)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["GROUP"] THEN [1] else [] END) |
        // (Group)-[:AZOwns]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (g)-[:AZOwns]->(azrg)
    	)
    	// (Group)-[:AZUserAccessAdministrator]->(AZResourceGroup)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azrg:AZResourceGroup {objectid: row.RGID})
    	  MERGE (g)-[:AZUserAccessAdministrator]->(azrg)
    	)
      )
    )
""")

print("[*] ()-[]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/kvpermissions.csv" AS row
    WITH row
    // (Azure Principal)-[]->(AZKeyVault)
    FOREACH(f in (CASE WHEN toUPPER(row.ControllerOnPremID) IS null THEN [1] else [] END) |
      //(AZUser)-[]->(AZKeyVault)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["USER"] THEN [1] else [] END) |
        // (AZUser)-[:AZOwns]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azu)-[:AZOwns]->(azkv)
    	)
        // (AZUser)-[:AZContributor]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azu)-[:AZContributor]->(azkv)
    	)
    	// (AZUser)-[:AZUserAccessAdministrator]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azu:AZUser {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azu)-[:AZUserAccessAdministrator]->(azkv)
    	)
      )
      //(AZGroup)-[]->(AZKeyVault)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["GROUP"] THEN [1] else [] END) |
        // (AZGroup)-[:AZOwns]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azg)-[:AZOwns]->(azkv)
    	)
        // (AZGroup)-[:AZContributor]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azg)-[:AZContributor]->(azkv)
    	)
    	// (AZGroup)-[:AZUserAccessAdministrator]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azg:AZGroup {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azg)-[:AZUserAccessAdministrator]->(azkv)
    	)
      )
      //(AZServicePrincipal)-[]->(AZKeyVault)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["SERVICE PRINCIPAL"] THEN [1] else [] END) |
        // (AZServicePrincipal)-[:AZOwns]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azsp)-[:AZOwns]->(azkv)
    	)
        // (AZServicePrincipal)-[:AZContributor]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azsp)-[:AZContributor]->(azkv)
    	)
    	// (AZServicePrincipal)-[:AZUserAccessAdministrator]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (azsp:AZServicePrincipal {objectid: row.ControllerID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (azsp)-[:AZUserAccessAdministrator]->(azkv)
    	)
      )
    )
    // (On-prem Principal)-[]->(AZKeyVault)
    FOREACH(f in (CASE WHEN NOT toUPPER(row.ControllerOnPremID) IS null THEN [1] else [] END) |
      //(User)-[]->(AZKeyVault)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["USER"] THEN [1] else [] END) |
        // (User)-[:AZOwns]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (u)-[:AZOwns]->(azkv)
    	)
        // (User)-[:AZContributor]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (u)-[:AZContributor]->(azkv)
    	)
    	// (User)-[:AZUserAccessAdministrator]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (u:User {objectid: row.ControllerOnPremID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (u)-[:AZUserAccessAdministrator]->(azkv)
    	)
      )
      //(Group)-[]->(AZKeyVault)
      FOREACH(f in (CASE WHEN toUPPER(row.ControllerType) IN ["GROUP"] THEN [1] else [] END) |
        // (Group)-[:AZOwns]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["OWNER"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (g)-[:AZOwns]->(azkv)
    	)
        // (Group)-[:AZContributor]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["CONTRIBUTOR"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (g)-[:AZContributor]->(azkv)
    	)
    	// (Group)-[:AZUserAccessAdministrator]->(AZKeyVault)
        FOREACH(f in (CASE WHEN toUPPER(row.RoleName) IN ["USER ACCESS ADMINISTRATOR"] THEN [1] else [] END) |
    	  MERGE (g:Group {objectid: row.ControllerOnPremID})
          MERGE (azkv:AZKeyVault {objectid: row.KVID})
    	  MERGE (g)-[:AZUserAccessAdministrator]->(azkv)
    	)
      )
    )
""")

print("[*] (OnPremPrincipal)-[AZ-GetKeys]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/kvaccesspolicies.csv" AS row
    WITH row
    WHERE toUpper(row.Access) = "GETKEYS" AND NOT row.ObjectOnPremID IS null
    MERGE (azkv:AZKeyVault {objectid: row.KVID})
    MERGE (n {objectid: row.ObjectOnPremID})
    MERGE (n)-[:AZGetKeys]->(azkv)
    """)    

print("[*] (CloudPrincipal)-[AZ-GetKeys]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/kvaccesspolicies.csv" AS row
    WITH row
    WHERE toUpper(row.Access) = "GETKEYS" AND row.ObjectOnPremID IS null
    MERGE (azkv:AZKeyVault {objectid: row.KVID})
    MERGE (n {objectid: row.ControllerID})
    MERGE (n)-[:AZGetKeys]->(azkv)
    """)
    
print("[*] (OnPremPrincipal)-[AZ-GetKeys]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/kvaccesspolicies.csv" AS row
    WITH row
    WHERE toUpper(row.Access) = "GETCERTIFICATES" AND NOT row.ObjectOnPremID IS null
    MERGE (azkv:AZKeyVault {objectid: row.KVID})
    MERGE (n {objectid: row.ObjectOnPremID})
    MERGE (n)-[:AZGetCertificates]->(azkv)
    """)    

print("[*] (CloudPrincipal)-[AZ-GetKeys]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/kvaccesspolicies.csv" AS row
    WITH row
    WHERE toUpper(row.Access) = "GETCERTIFICATES" AND row.ObjectOnPremID IS null
    MERGE (azkv:AZKeyVault {objectid: row.KVID})
    MERGE (n {objectid: row.ControllerID})
    MERGE (n)-[:AZGetCertificates]->(azkv)
    """)
    
print("[*] (OnPremPrincipal)-[AZ-GetKeys]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/kvaccesspolicies.csv" AS row
    WITH row
    WHERE toUpper(row.Access) = "GETSECRETS" AND NOT row.ObjectOnPremID IS null
    MERGE (azkv:AZKeyVault {objectid: row.KVID})
    MERGE (n {objectid: row.ObjectOnPremID})
    MERGE (n)-[:AZGetSecrets]->(azkv)
    """)    

print("[*] (CloudPrincipal)-[AZ-GetKeys]->(AZKeyVault)")
driver.run_query("""
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/kvaccesspolicies.csv" AS row
    WITH row
    WHERE toUpper(row.Access) = "GETSECRETS" AND row.ObjectOnPremID IS null
    MERGE (azkv:AZKeyVault {objectid: row.KVID})
    MERGE (n {objectid: row.ControllerID})
    MERGE (n)-[:AZGetSecrets]->(azkv)
    """)

print("[*] (AzureUser)-[:AZResetPassword]->(AzureUser)")
driver.run_query("""
    // Password reset rights
    // (AzureUser)-[:AZResetPassword]->(AzureUser)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/pwresetrights.csv" AS row
    WITH row
    WHERE row.UserOnPremID IS null AND row.TargetUserOnPremID IS null
    MERGE (azu1:AZUser {objectid: row.UserID})
    MERGE (azu2:AZUser {objectid: row.TargetUserID})
    MERGE (azu1)-[:AZResetPassword]->(azu2)
""")

print("[*] (AzureUser)-[:AZResetPassword]->(User)")
driver.run_query("""
    // Password reset rights
    // (AzureUser)-[:AZResetPassword]->(User)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/pwresetrights.csv" AS row
    WITH row
    WHERE row.UserOnPremID IS null AND NOT row.TargetUserOnPremID IS null
    MERGE (azu:AZUser {objectid: row.UserID})
    MERGE (u:User {objectid: row.TargetUserOnPremID})
    MERGE (azu)-[:AZResetPassword]->(u)
""")

print("[*] (User)-[:AZResetPassword]->(AzureUser)")
driver.run_query("""
    // Password reset rights
    // (User)-[:AZResetPassword]->(AzureUser)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/pwresetrights.csv" AS row
    WITH row
    WHERE NOT row.UserOnPremID IS null AND row.TargetUserOnPremID IS null
    MERGE (u:User {objectid: row.UserOnPremID})
    MERGE (azu:AZUser {objectid: row.TargetUserID})
    MERGE (u)-[:AZResetPassword]->(azu)
""")

print("[*] (User)-[:AZResetPassword]->(User)")
driver.run_query("""
    // Password reset rights
    // (User)-[:AZResetPassword]->(User)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/pwresetrights.csv" AS row
    WITH row
    WHERE NOT row.UserOnPremID IS null AND NOT row.TargetUserOnPremID IS null
    MERGE (u1:User {objectid: row.UserOnPremID})
    MERGE (u2:User {objectid: row.TargetUserOnPremID})
    MERGE (u1)-[:AZResetPassword]->(u2)
""")

print("[*] (AzureUser)-[:AZAddMembers]->(AzureGroup)")
driver.run_query("""
    // Right to add principal to cloud group
    // (AzureUser)-[:AZAddMembers]->(AzureGroup)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/groupsrights.csv" AS row
    WITH row
    WHERE row.UserOnPremID IS null
    MERGE (azu:AZUser {objectid: row.UserID})
    MERGE (azg:AZGroup {objectid: row.TargetGroupID})
    MERGE (azu)-[:AZAddMembers]->(azg)
""")

print("[*] (User)-[:AZAddMembers]->(AzureGroup)")
driver.run_query("""
    // Right to add principal to cloud group
    // (User)-[:AZAddMembers]->(AzureGroup)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/groupsrights.csv" AS row
    WITH row
    WHERE NOT row.UserOnPremID IS null
    MERGE (u:User {objectid: row.UserOnPremID})
    MERGE (azg:AZGroup {objectid: row.TargetGroupID})
    MERGE (azu)-[:AZAddMembers]->(azg)
""")

print("[*] (AzureUser)-[:AZGlobalAdmin]->(Tenant)")
driver.run_query("""
    // Global admin rights
    // (AzureUser)-[:AZGlobalAdmin]->(Tenant)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/globaladminrights.csv" AS row
    WITH row
    WHERE row.UserOnPremID IS null
    MERGE (azu:AZUser {objectid: row.UserID})
    MERGE (azt:AZTenant {objectid: row.TenantID})
    MERGE (azu)-[:AZGlobalAdmin]->(azt)
""")

print("[*] (User)-[:AZGlobalAdmin]->(Tenant)")
driver.run_query("""
    // Global admin rights
    // (User)-[:AZGlobalAdmin]->(Tenant)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/globaladminrights.csv" AS row
    WITH row
    WHERE NOT row.UserOnPremID IS null
    MERGE (u:User {objectid: row.UserOnPremID})
    MERGE (azt:AZTenant {objectid: row.TenantID})
    MERGE (u)-[:AZGlobalAdmin]->(azt)
""")

print("[*] (AzureUser)-[:AZPrivilegedRoleAdmin]->(Tenant)")
driver.run_query("""
    // Privileged role admin
    // (AzureUser)-[:AZPrivilegedRoleAdmin]->(Tenant)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/privroleadminrights.csv" AS row
    WITH row
    WHERE row.UserOnPremID IS null
    MERGE (azu:AZUser {objectid: row.UserID})
    MERGE (azt:AZTenant {objectid: row.TenantID})
    MERGE (azu)-[:AZPrivilegedRoleAdmin]->(azt)
""")

print("[*] (User)-[:AZPrivilegedRoleAdmin]->(Tenant)")
driver.run_query("""
    // Privileged role admin
    // (User)-[:AZPrivilegedRoleAdmin]->(Tenant)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/privroleadminrights.csv" AS row
    WITH row
    WHERE NOT row.UserOnPremID IS null
    MERGE (u:User {objectid: row.UserOnPremID})
    MERGE (azt:AZTenant {objectid: row.TenantID})
    MERGE (u)-[:AZPrivilegedRoleAdmin]->(azt)
""")

print("[*] (User)-[:AZOwns]->(AZApp)")
driver.run_query("""
    // On-prem user owns azure app
    // (User)-[:AZOwns]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/applicationowners.csv" AS row
    WITH row
    WHERE NOT row.OwnerOnPremID IS null AND row.OwnerType = "User"
    MERGE (u:User {objectid: row.OwnerOnPremID})
    MERGE (aza:AZApp {objectid: row.AppObjectId})
    MERGE (u)-[:AZOwns]->(aza)
    SET aza.name = row.AppDisplayname
""")

print("[*] (AZUser)-[:AZOwns]->(AZApp)")
driver.run_query("""
    // Cloud user owns azure app
    // (AZUser)-[:AZOwns]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/applicationowners.csv" AS row
    WITH row
    WHERE row.OwnerOnPremID IS null AND row.OwnerType = "User"
    MERGE (azu:AZUser {objectid: row.OwnerID})
    MERGE (aza:AZApp {objectid: row.AppObjectId})
    MERGE (u)-[:AZOwns]->(aza)
    SET aza.name = row.AppDisplayname
""")

print("[*] (AZServicePrincipal)-[:AZOwns]->(AZApp)")
driver.run_query("""
    // Service Principal owns azure app
    // (AZServicePrincipal)-[:AZOwns]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/applicationowners.csv" AS row
    WITH row
    WHERE row.OwnerType = "ServicePrincipal"
    MERGE (azsp:AZServicePrincipal {objectid: row.OwnerID})
    MERGE (aza:AZApp {objectid: row.AppObjectId})
    MERGE (azsp)-[:AZOwns]->(aza)
    SET aza.name = row.AppDisplayname
""")

print("[*] (AZApp)-[:AZRunsAs]->(AZServicePrincipal)")
driver.run_query("""
    // Azure app runs as service principal
    // (AZApp)-[:AZRunsAs]->(AZServicePrincipal)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/serviceprincipalowners.csv" AS row
    WITH row
    MERGE (aza:AZApp {objectid: row.AppObjectId})
    MERGE (azsp:AZServicePrincipal {objectid: row.ServicePrincipalId})
    MERGE (aza)-[:AZRunsAs]->(azsp)
""")

print("[*] (User)-[:AZOwns]->(AZServicePrincipal)")
driver.run_query("""
    // On-prem user owns service principal
    // (User)-[:AZOwns]->(AZServicePrincipal)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/serviceprincipalowners.csv" AS row
    WITH row
    WHERE NOT row.ServicePrincipalOwnerOnPremID IS null AND row.OwnerType = "User"
    MERGE (u:User {objectid: row.ServicePrincipalOwnerOnPremID})
    MERGE (azsp:AZServicePrincipal {objectid: row.ServicePrincipalId})
    MERGE (u)-[:AZOwns]->(azsp)
    SET azsp.name = row.ServicePrincipalDisplayName
""")

print("[*] (AZUser)-[:AZOwns]->(AZServicePrincipal)")
driver.run_query("""
    // Cloud user owns azure app
    // (AZUser)-[:AZOwns]->(AZServicePrincipal)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/serviceprincipalowners.csv" AS row
    WITH row
    WHERE row.ServicePrincipalOwnerOnPremID IS null AND row.OwnerType = "User"
    MERGE (azu:AZUser {objectid: row.ServicePrincipalOwnerId})
    MERGE (azsp:AZServicePrincipal {objectid: row.ServicePrincipalId})
    MERGE (u)-[:AZOwns]->(azsp)
    SET azsp.name = row.ServicePrincipalDisplayName
""")

print("[*] (AZServicePrincipal)-[:AZOwns]->(AZServicePrincipal)")
driver.run_query("""
    // Cloud user owns azure app
    // (AZUser)-[:AZOwns]->(AZServicePrincipal)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/serviceprincipalowners.csv" AS row
    WITH row
    WHERE row.OwnerType = "ServicePrincipal"
    MERGE (azsp1:AZServicePrincipal {objectid: row.ServicePrincipalOwnerId})
    MERGE (azsp2:AZServicePrincipal {objectid: row.ServicePrincipalId})
    MERGE (azsp1)-[:AZOwns]->(azsp2)
    SET azsp2.name = row.ServicePrincipalDisplayName
""")

print("[*] (AZUser)-[:AZAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZUser)-[:AZAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "User" AND row.PrincipalOnPremID IS null AND row.AdminRoleName = "AppAdmin"
    MERGE (azu:AZUser {objectid: row.PrincipalID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (azu)-[:AZAppAdmin]->(aza)
""")

print("[*] (User)-[:AZAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZUser)-[:AZAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "User" AND NOT row.PrincipalOnPremID IS null AND row.AdminRoleName = "AppAdmin"
    MERGE (u:User {objectid: row.PrincipalOnPremID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (u)-[:AZAppAdmin]->(aza)
""")

print("[*] (AZGroup)-[:AZAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZGroup)-[:AZAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "Group" AND row.AdminRoleName = "AppAdmin"
    MERGE (azg:AZGroup {objectid: row.PrincipalID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (azg)-[:AZAppAdmin]->(aza)
""")

print("[*] (AZServicePrincipal)-[:AZAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZServicePrincipal)-[:AZAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "ServicePrincipal" AND row.AdminRoleName = "AppAdmin"
    MERGE (azsp:AZServicePrincipal {objectid: row.PrincipalID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (azsp)-[:AZAppAdmin]->(aza)
""")

print("[*] (AZUser)-[:AZCloudAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZUser)-[:AZCloudAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "User" AND row.PrincipalOnPremID IS null AND row.AdminRoleName = "CloudAppAdmin"
    MERGE (azu:AZUser {objectid: row.PrincipalID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (azu)-[:AZCloudAppAdmin]->(aza)
""")

print("[*] (User)-[:AZCloudAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZUser)-[:AZCloudAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "User" AND NOT row.PrincipalOnPremID IS null AND row.AdminRoleName = "CloudAppAdmin"
    MERGE (u:User {objectid: row.PrincipalOnPremID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (u)-[:AZCloudAppAdmin]->(aza)
""")

print("[*] (AZGroup)-[:AZCloudAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZGroup)-[:AZCloudAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "Group" AND row.AdminRoleName = "CloudAppAdmin"
    MERGE (azg:AZGroup {objectid: row.PrincipalID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (azg)-[:AZCloudAppAdmin]->(aza)
""")

print("[*] (AZServicePrincipal)-[:AZCloudAppAdmin]->(AZApp)")
driver.run_query("""
    // Cloud user has App Admin role against azure app
    // (AZServicePrincipal)-[:AZCloudAppAdmin]->(AZApp)
    LOAD CSV WITH HEADERS FROM "file:///c:/users/wald0/apprights.csv" AS row
    WITH row
    WHERE row.PrincipalType = "ServicePrincipal" AND row.AdminRoleName = "CloudAppAdmin"
    MERGE (azsp:AZServicePrincipal {objectid: row.PrincipalID})
    MERGE (aza:AZApp {objectid: row.AppObjectID})
    MERGE (azsp)-[:AZCloudAppAdmin]->(aza)
""")

print("Done.")
