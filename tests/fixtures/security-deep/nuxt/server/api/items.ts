export default defineEventHandler((request) => {
 return fetch(request.query.url);
});
