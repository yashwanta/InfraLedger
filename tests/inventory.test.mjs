import {test} from 'node:test';
import assert from 'node:assert/strict';
import {inventoryRecords} from '../web/src/inventory.ts';

test('pending devices and their linked observations stay out of inventory',()=>{
 const records=[{id:'pending',type:'assets',approvalStatus:'Pending'},{id:'service',type:'services',assetId:'pending'},{id:'flow',type:'dependencies',sourceId:'service',targetId:'pending'},{id:'approved',type:'assets',approvalStatus:'Approved'},{id:'article',type:'articles'}];
 assert.deepEqual(inventoryRecords(records).map(r=>r.id),['approved','article']);
});
test('approved guests wait for their pending virtualization parent',()=>{
 const records=[{id:'host',type:'assets',approvalStatus:'Pending'},{id:'vm',type:'assets',hostId:'host',approvalStatus:'Approved'},{id:'service',type:'services',assetId:'vm'}];
 assert.deepEqual(inventoryRecords(records),[]);
 records[0].approvalStatus='Approved';assert.equal(inventoryRecords(records).length,3);
});
test('existing inventory without an approval flag remains visible',()=>{
 const records=[{id:'legacy',type:'assets'},{id:'manual',type:'assets',approvalStatus:'Approved'}];assert.equal(inventoryRecords(records).length,2);
});
