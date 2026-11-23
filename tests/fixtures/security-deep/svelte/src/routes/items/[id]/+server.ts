export const GET = async ({params, request}) => {
 const item = await db.items.findUnique({where: {id: params.id}});
 requireAuth(request);
 return item;
};
