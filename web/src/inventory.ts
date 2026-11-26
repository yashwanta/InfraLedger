import type {Item} from './model';

export function inventoryRecords(records:Item[]):Item[]{
 const pending=new Set(records.filter(r=>r.type==='assets'&&r.approvalStatus==='Pending').map(r=>r.id));
 let changed=true;while(changed){changed=false;for(const r of records)if(!pending.has(r.id)&&['assetId','hostId','sourceId','targetId','connectedAssetId'].some(key=>typeof r[key]==='string'&&pending.has(r[key] as string))){pending.add(r.id);changed=true}}
 return records.filter(r=>r.approvalStatus!=='Pending'&&!pending.has(r.id)&&!['assetId','hostId','sourceId','targetId','connectedAssetId'].some(key=>typeof r[key]==='string'&&pending.has(r[key] as string)));
}
