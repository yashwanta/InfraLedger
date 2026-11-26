import { defineConfig } from 'vite';
export default defineConfig({root:'web',publicDir:'../public-assets',build:{outDir:'../dist',emptyOutDir:true},server:{host:'127.0.0.1',port:5175,proxy:{'/api':'http://127.0.0.1:5173'}}});
