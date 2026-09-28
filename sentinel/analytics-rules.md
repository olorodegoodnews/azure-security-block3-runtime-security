# Microsoft Sentinel Analytics Rules

## 1. Azure Resource Group Deletion

- **Severity:** Medium
- **Log Source:** Azure Activity
- **Table:** `AzureActivity`
- **Purpose:** Detect successful deletion of an Azure resource group.
- **Status:** Validated
- **KQL:** `../detections/01-resource-group-deletion.kql`

---

## 2. Azure RBAC Role Assignment Change

- **Severity:** Medium
- **Log Source:** Azure Activity
- **Table:** `AzureActivity`
- **Purpose:** Detect creation, modification, or deletion of Azure RBAC role assignments.
- **Status:** Validated
- **KQL:** `../detections/02-rbac-role-assignment-changes.kql`

---

## 3. Azure Policy Assignment Change

- **Severity:** Medium
- **Log Source:** Azure Activity
- **Table:** `AzureActivity`
- **Purpose:** Detect creation, modification, or deletion of Azure Policy assignments.
- **Status:** Validated
- **KQL:** `../detections/03-azure-policy-assignment-changes.kql`

---

## 4. Azure NSG Security Rule Change

- **Severity:** Medium
- **Log Source:** Azure Activity
- **Table:** `AzureActivity`
- **Purpose:** Detect creation, modification, or deletion of Network Security Group security rules.
- **Status:** Validated
- **KQL:** `../detections/04-nsg-rule-changes.kql`

---

## Additional Detection Work

### Azure Key Vault Access Policy Change

A Key Vault access-policy detection was also configured and tested as additional work.

It is not counted among the four fully validated detections because final event and incident validation were not completed.
