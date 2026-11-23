export function OrdersCard({ orders }: { orders: any[] }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold">Zamówienia</h3>
        <a className="text-xs underline" href="/orders">Wszystkie</a>
      </div>
      <ul className="divide-y">
        {orders.map((o) => (<li key={o.id} className="flex justify-between py-2 text-sm"><span>{o.number}</span><span>{o.total}</span></li>))}
      </ul>
      <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold bg-amber-100 text-amber-800">Oczekuje</span>
    </div>
  );
}
