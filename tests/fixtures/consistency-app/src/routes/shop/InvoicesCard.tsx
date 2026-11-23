export function InvoicesCard({ invoices }: { invoices: any[] }) {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold">Faktury</h3>
        <a className="text-xs underline" href="/invoices">Wszystkie</a>
      </div>
      <ul className="divide-y">
        {invoices.map((i) => (<li key={i.id} className="flex justify-between py-2 text-sm"><span>{i.number}</span><span>{i.amount}</span></li>))}
      </ul>
      <button className="mt-2 text-[13px]">Pobierz</button>
    </div>
  );
}
