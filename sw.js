// public/sw.js

self.addEventListener('install', (event) => {
    console.log('Service Worker installed');
    self.skipWaiting();
  });
  
  self.addEventListener('activate', (event) => {
    console.log('Service Worker activated');
  });
  
  self.addEventListener('fetch', (event) => {
    // You can add caching logic here if you like,
    // for now just pass through all requests:
    event.respondWith(fetch(event.request));
  });
  