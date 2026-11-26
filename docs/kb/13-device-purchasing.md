# User guide — Device purchasing

Track device purchases from request to delivery, and receive them straight into inventory.

## Create a purchase order

1. Select **New purchase order** and choose the organization.
2. Enter the vendor, device naming prefix, device type, model, quantity, unit cost, currency and expected delivery date.
3. Select **Create record**. The order starts as **Draft**.

## Workflow

Open the order and use the action button to move it forward:

1. **Draft:** select **Submit for approval**.
2. **Submitted:** an admin selects **Approve order**.
3. **Approved:** select **Mark as ordered**.
4. **Ordered:** select **Receive devices into inventory**.

Receiving creates one asset per unit, named from the prefix (for example `LAPTOP-001`, `LAPTOP-002`), with status **In stock** and the unit cost. Received devices are listed on the order.

## Notes

- Orders can be cancelled at any stage before they are received.
- These steps are internal records only: InfraLedger does not send orders to vendors or make payments.
