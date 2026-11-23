// Existing Helix geometry rules; synchronous per-render caches. No Node dependencies.
export function auditDOM([ladder, tapMin, leadMax, space]) {
	const styles = new WeakMap(), rects = new WeakMap();
	const styleOf = (el, pseudo) => {
		if (pseudo) return getComputedStyle(el, pseudo);
		if (!styles.has(el)) styles.set(el, getComputedStyle(el));
		return styles.get(el);
	};
	const rectOf = (el) => {
		if (!rects.has(el)) rects.set(el, el.getBoundingClientRect());
		return rects.get(el);
	};
	const hiddenCache = new WeakMap();
	const hiddenByParent = (el) => {
		if (!el) return false;
		if (!hiddenCache.has(el)) hiddenCache.set(el,
			+styleOf(el).opacity === 0 || styleOf(el).display === 'none' || hiddenByParent(el.parentElement));
		return hiddenCache.get(el);
	};
	const vis = (el) => {
		const s = styleOf(el);
		const b = rectOf(el);
		// zamknięte <details>: treść poza <summary> ma wymiary (content-visibility), ale nie jest widoczna
		const d = el.closest('details');
		if (d && !d.open && !el.closest('summary')) return false;
		return !hiddenByParent(el) && s.visibility !== 'hidden' && s.visibility !== 'collapse' && b.width > 0 && b.height > 0;
	};
	const label = (el) =>
		(el.tagName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).slice(0, 2).join('.') : '') +
			' "' + (el.innerText || el.getAttribute('aria-label') || '').trim().slice(0, 30) + '"');
	const out = { hscroll: document.documentElement.scrollWidth > innerWidth + 1, tap: [], font: {}, contrast: [], clip: [], warn: [], a11y: [], rhythm: [], lead: [], edge: [], axis: [], gap: [] };
	const ignored = document.querySelectorAll('[data-helix-ignore]').length;
	if (ignored) out.warn.push(`Pominięto ${ignored} elementów (data-helix-ignore) wraz z potomkami`);
	// Small, explicit accessibility checks, not a claim of complete WCAG coverage.
	const nameOf = el => {
		const refs = (el.getAttribute('aria-labelledby') || '').split(/\s+/).filter(Boolean);
		return refs.map(id => document.getElementById(id)?.textContent || '').join(' ').trim()
			|| el.getAttribute('aria-label')?.trim() || el.getAttribute('title')?.trim()
			|| [...(el.labels || [])].map(l => l.textContent).join(' ').trim()
			|| (el.matches('button,a,[role=button],summary') ? (el.textContent || '').trim() || [...el.querySelectorAll('img')].map(i => i.alt).join('').trim() || el.querySelector('svg title')?.textContent : '')
			|| (el.matches('input[type=submit],input[type=reset]') ? el.value || (el.type === 'submit' ? 'Submit' : 'Reset') : el.matches('input[type=button]') ? el.value : '');
	};
	for (const el of document.querySelectorAll('button,[role=button],a[href],input,select,textarea,summary,img')) {
		if (!vis(el) || el.closest('[data-helix-ignore]') || el.matches('input[type=hidden]')) continue;
		if (el.tagName === 'IMG') {
			if (!el.hasAttribute('alt') && !el.matches('[role=presentation],[role=none],[aria-hidden=true]') && !nameOf(el)) out.a11y.push(`obraz bez opisu alt: ${label(el)}`);
		} else if (!nameOf(el)) out.a11y.push(`kontrolka bez nazwy dostępnej: ${label(el)}`);
	}

	// cel dotyku: obszar klikalny liczy się z ::after (rozszerzenie hitboxu), inline linki w tekście pomijamy
	for (const el of document.querySelectorAll('button,[role=button],a[href],input,select,textarea,summary')) {
		if (!vis(el) || el.closest('[data-helix-ignore]')) continue;
		const s = styleOf(el);
		if (el.tagName === 'A' && s.display === 'inline') continue;
		// pole wyboru w etykiecie: celem dotyku jest cała etykieta (kliknięcie w nią przełącza pole)
		const b = (/checkbox|radio/.test(el.type) && el.closest('label') ? el.closest('label') : el).getBoundingClientRect();
		if (b.width <= 2 && b.height <= 2) continue; // .sr-only (np. pole pliku pod etykietą-strefą) nie jest celem dotyku
		const af = styleOf(el, '::after');
		const ext = af.content !== 'none' && af.position === 'absolute' ? Math.max(0, -parseFloat(af.top) || 0) * 2 : 0;
		const extX = af.content !== 'none' && af.position === 'absolute' ? Math.max(0, -parseFloat(af.left) || 0) * 2 : 0;
		if (b.height + ext < tapMin || b.width + extX < tapMin) out.tap.push(`${label(el)} ${Math.round(b.width)}×${Math.round(b.height)}`);
		// wartość liczbowa ucięta WEWNĄTRZ pola („1500” widoczne jako „150”) — tekst w input nie jest w drzewie tekstu
		if (el.tagName === 'INPUT' && /\d/.test(el.value) && (el.value.match(/\p{L}/gu) || []).length <= 4 && !/date|time|range|checkbox|radio|hidden/.test(el.type) && el.scrollWidth > el.clientWidth + 1)
			out.clip.push(`ucięte w polu „${el.value}”: ${label(el)}`);
	}
	// ramka ucięta przez przewijany kontener (właściciel, pigułki widoków): element z ramką poza swoim pudełkiem
	// (box-shadow 0 0 0 Npx albo border) siedzi równo z krawędzią przodka, który ma overflow ≠ visible → przodek ucina ramkę z tej strony
	for (const el of document.querySelectorAll('*')) {
		if (!vis(el) || el.closest('[data-helix-ignore]')) continue;
		const s = styleOf(el);
		const ring = (s.boxShadow.match(/(?:^|,)\s*(?:rgba?\([^)]*\)\s*)?0px 0px 0px (\d+(?:\.\d+)?)px/) || [])[1];
		const ringPx = ring ? parseFloat(ring) : 0;
		const outline = s.outlineStyle !== 'none' ? parseFloat(s.outlineWidth) || 0 : 0;
		if (ringPx < 1 && outline < 1) continue; // border rysuje się wewnątrz pudełka — scroll go nie tnie
		if (parseFloat(s.borderTopLeftRadius) < 8) continue; // pigułki, karty, pola: ramka jest częścią kształtu
		const r0 = rectOf(el);
		if (r0.width < 40 || r0.height < 20) continue;
		for (let a = el.parentElement; a && a !== document.documentElement && a !== document.body; a = a.parentElement) { // body/viewport tnie ramę aplikacji z założenia
			const as = styleOf(a);
			if (as.overflow === 'visible' && as.overflowX === 'visible' && as.overflowY === 'visible') continue;
			const ra = rectOf(a);
			const pad = { t: parseFloat(as.paddingTop) || 0, l: parseFloat(as.paddingLeft) || 0, b: parseFloat(as.paddingBottom) || 0, r: parseFloat(as.paddingRight) || 0 };
			const grubosc = Math.max(ringPx, outline);
			const strony = [];
			// Element, który wychodzi poza krawędź przewijanego kontenera, jest po prostu dalej na liście (przewinie się): to nie ucięta ramka.
			// Ucięta ramka to element stojący przy samej krawędzi, którego obwódka nie ma już gdzie się zmieścić.
			const przewijaY = /auto|scroll/.test(as.overflowY) && a.scrollHeight > a.clientHeight + 1;
			const przewijaX = /auto|scroll/.test(as.overflowX) && a.scrollWidth > a.clientWidth + 1;
			const poza = (odleglosc, przewija) => przewija && odleglosc < -grubosc;
			if (r0.top - ra.top < grubosc - 0.01 && pad.t < grubosc && !poza(r0.top - ra.top, przewijaY)) strony.push('góra');
			if (r0.left - ra.left < grubosc - 0.01 && pad.l < grubosc && !poza(r0.left - ra.left, przewijaX)) strony.push('lewa');
			if (ra.bottom - r0.bottom < grubosc - 0.01 && pad.b < grubosc && !poza(ra.bottom - r0.bottom, przewijaY)) strony.push('dół');
			if (ra.right - r0.right < grubosc - 0.01 && pad.r < grubosc && !poza(ra.right - r0.right, przewijaX)) strony.push('prawa');
			if (strony.length) out.clip.push(`ramka ucięta (${strony.join(', ')}) przez ${a.tagName.toLowerCase()}.${(a.getAttribute('class') || '').split(' ')[0]} z overflow: ${label(el)}`);
			break; // liczy się najbliższy kontener tnący
		}
	}
	// rytm list: w kontenerach-kartach (promień ≥ 12) wiersze (≥ 2 dzieci, wys. ≥ 36, szer. ≥ 70 % karty) zaczynają tekst
	// w tych samych odległościach od lewej krawędzi karty; więcej niż leadMax skupisk (±2 px) = bloker
	// („Wymaga uwagi” z kropką 8 px obok „Spotkania” z kolumną 48 px drażniło właściciela).
	{
		const starts = [];
		for (const c of document.querySelectorAll('body *')) {
			if (!vis(c) || c.closest('[data-helix-ignore]') || parseFloat(styleOf(c).borderTopLeftRadius) < 12) continue;
			const cb = rectOf(c);
			const big = [...c.children].filter((k) => { const b = rectOf(k); return vis(k) && b.height >= 36 && b.width >= cb.width * 0.7; });
			// wiersze listy = rodzeństwo tego samego rodzaju (znacznik + pierwsza klasa); nagłówek, treść i stopka szuflady
			// albo karta podsumowania (suma, przyciski, opiekun) to nie lista i nie mają wspólnej kolumny tekstu
			const sig = (k) => k.tagName + '.' + ((typeof k.className === 'string' && k.className.trim().split(/\s+/)[0]) || '');
			const cnt = {};
			for (const k of big) cnt[sig(k)] = (cnt[sig(k)] || 0) + 1;
			const kids = big.filter((k) => cnt[sig(k)] >= 2);
			if (kids.length < 2) continue;
			for (const k of kids) {
				// kolumna tekstu wiersza = najszersze dziecko z tekstem (kolumna wiodąca z datą/kodem jest wąska i nie liczy się)
				const firstText = (root) => {
					const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
					let tn = null;
					// napis przycisku wewnątrz wiersza i tekst wyśrodkowany nie tworzą kolumny tekstu
					const skip = (e) => { const bt = e.closest('.ui-btn,button'); return styleOf(e).textAlign === 'center' || (bt && bt !== root && root.contains(bt)); };
					while ((tn = w.nextNode())) if (tn.textContent.trim() && vis(tn.parentElement) && styleOf(tn.parentElement).position !== 'absolute' && !skip(tn.parentElement)) return tn;
					return null;
				};
				const cols = [...k.children].filter((c2) => vis(c2) && firstText(c2));
				// kolumna tekstu = najszersze dziecko z tekstem (elastyczna kolumna wiersza); remis → pierwsze.
				// Nie „najwięcej znaków”: kolumna ilości „1 szt. × 100,00” ma ich więcej niż nazwa „Pozycja”, a nie jest kolumną tekstu.
				// Pastylki i kwoty mają white-space: nowrap i na 280 px bywają szersze od ściśniętego tekstu: liczą się dopiero, gdy nie ma kolumny łamiącej.
				const wd = (e) => rectOf(e).width;
				const wrapCols = cols.filter((c2) => styleOf(c2).whiteSpace !== 'nowrap');
				const pool = wrapCols.length ? wrapCols : cols;
				const col = pool.length ? pool.reduce((a, b) => (wd(b) > wd(a) + 1 ? b : a)) : k;
				const tn = firstText(col);
				if (!tn) continue;
				const rg = document.createRange(); rg.selectNodeContents(tn);
				const r = [...rg.getClientRects()].find((q) => q.width > 0);
				if (r) starts.push({ off: Math.round(r.left - cb.left), el: label(k) });
				// kolumna wiodąca (≤ 64 px: ikona, data, kod) ma stać na osi kolumny tekstu, nie całego wiersza
				// (właściciel: „te ikony nie są wyśrodkowane, tu znowu inne wysokości”)
				const lead = k.firstElementChild;
				// tylko kolumna OBOK tekstu: plakietka nad opisem (układ piętrowy na telefonie) nie jest kolumną wiodącą
				if (lead && lead !== col && vis(lead) && rectOf(lead).width <= 64 && rectOf(lead).right <= rectOf(col).left + 1 && (lead.querySelector('svg,img') || (lead.innerText || '').trim())) {
					// oś = środek kolumny tekstu (wiersz 1-2 linie) ALBO środek jej pierwszej linii (długi tekst: ikona przy tytule)
					const lb = rectOf(lead);
					// tekst piętrowy (telefon: tytuł z opisem, pod nimi wartość na pełną szerokość) = jedna kolumna tekstu:
					// oś liczona ze wspólnego prostokąta, nie z wartości, która bywa najszersza
					const cr = rectOf(col);
					const pietro = pool.filter((c2) => { const q = rectOf(c2); return q.left < cr.right - 1 && q.right > cr.left + 1 && q.left >= lb.right - 1; });
					const tb = pietro.reduce((u, c2) => { const q = rectOf(c2); return { top: Math.min(u.top, q.top), bottom: Math.max(u.bottom, q.bottom), get height() { return this.bottom - this.top; } }; }, { top: cr.top, bottom: cr.bottom, get height() { return this.bottom - this.top; } });
					const rg1 = document.createRange(); rg1.selectNodeContents(tn);
					const l1 = [...rg1.getClientRects()].find((q) => q.width > 0) || tb;
					const lc = lb.top + lb.height / 2;
					const d = Math.round(Math.min(Math.abs(lc - (tb.top + tb.height / 2)), Math.abs(lc - (l1.top + l1.height / 2))));
					if (d > 3) out.lead.push(`${label(k)} kolumna wiodąca ${d}px od osi tekstu`);
				}
			}
		}
		const groups = [];
		for (const st of starts.sort((a, b) => a.off - b.off)) {
			const g = groups.find((x) => Math.abs(x.off - st.off) <= 2);
			if (g) g.n++; else groups.push({ off: st.off, n: 1, el: st.el });
		}
		if (groups.length > leadMax) out.rhythm = groups.map((g) => `${g.off}px ×${g.n} (np. ${g.el})`);
	}
	const rgba = (c) => {
		if (!/^(rgba?\(|color\(srgb )/.test(c)) return null;
		const values = c.match(/-?\d*\.?\d+(?:e[-+]?\d+)?/gi)?.map(Number);
		if (!values || values.length < 3) return null;
		const unit = c.startsWith('color(') ? 1 : 255;
		return { rgb: values.slice(0, 3).map(v => Math.max(0, Math.min(1, v / unit))), a: values[3] ?? 1 };
	};
	const luminance = (rgb) => rgb.map(v => v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
		.reduce((v, c, i) => v + c * [0.2126, 0.7152, 0.0722][i], 0);
	const lum = c => { const v = rgba(c); return v ? { L: luminance(v.rgb), a: v.a } : null; };
	const blend = (fg, bg, a) => fg.map((v, i) => v * a + bg[i] * (1 - a));
	// Paint foreground and background through each ancestor including opacity groups.
	// Gradients/images/unsupported color spaces cannot be inferred from computed CSS: report a limitation.
	const textContrast = el => {
		const fg = rgba(styleOf(el).color);
		if (!fg) return null;
		let ink = fg.rgb, ia = fg.a, bg = [0, 0, 0], ba = 0;
		for (let e = el; e; e = e.parentElement) {
			const st = styleOf(e), c = rgba(st.backgroundColor);
			if (!c || st.backgroundImage !== 'none' || st.mixBlendMode !== 'normal' || st.filter !== 'none') return null;
			const over = (rgb, a) => {
				const combined = a + c.a * (1 - a);
				return [combined ? rgb.map((v, i) => (v * a + c.rgb[i] * c.a * (1 - a)) / combined) : rgb, combined];
			};
			[ink, ia] = over(ink, ia); [bg, ba] = over(bg, ba);
			ia *= +st.opacity; ba *= +st.opacity;
		}
		const l1 = luminance(blend(ink, [1, 1, 1], ia)), l2 = luminance(blend(bg, [1, 1, 1], ba));
		return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
	};
	// ——— wyrównanie i odstępy (właściciel: „wyrównanie, odstępy, itp., dlaczego helix tego nie wyłapuje”) ———
	const alpha = (c) => (c ? lum(c)?.a ?? 0 : 0);
	// cień widoczny = kolor z alfą i choć jedna niezerowa długość (Tailwind zostawia „rgba(0,0,0,0) 0px 0px 0px 0px”)
	const shadowVisible = (bs) =>
		bs !== 'none' &&
		bs.split(/,(?![^(]*\))/).some((part) => {
			const col = (part.match(/(rgba?|color)\([^)]*\)/) || [])[0];
			const lens = part.replace(col || '', '').match(/-?[\d.]+px/g) || [];
			return alpha(col) > 0.05 && lens.some((v) => parseFloat(v) !== 0);
		});
	const boxCache = new Map();
	// pudełko widać: tło, ramka albo cień
	const boxed = (e) => {
		if (boxCache.has(e)) return boxCache.get(e);
		const st = styleOf(e);
		const v =
			alpha(st.backgroundColor) > 0.05 ||
			(parseFloat(st.borderLeftWidth) > 0 && alpha(st.borderLeftColor) > 0.1) ||
			(parseFloat(st.borderTopWidth) > 0 && alpha(st.borderTopColor) > 0.1) ||
			shadowVisible(st.boxShadow) ||
			// pigułka (link/przycisk z promieniem ≥ 16 i paddingiem): tekst wcięty celowo, tło pojawia się na hover
			// i przy aktywnej pozycji (zakładki ViewTabs, pasek sekcji); nie jest to „prawie równa” kolumna
			(/^(A|BUTTON)$/.test(e.tagName) && parseFloat(st.borderTopLeftRadius) >= 16 && parseFloat(st.paddingLeft) >= 8);
		boxCache.set(e, v);
		return v;
	};
	// pole z ramką: tekst i placeholder nie dotykają krawędzi (textarea bez paddingu = tekst na ramce)
	for (const el of document.querySelectorAll('input,textarea,select')) {
		if (!vis(el) || el.closest('[data-helix-ignore]')) continue;
		if (/^(checkbox|radio|range|color|file|hidden|submit|button|image|reset)$/.test(el.type)) continue;
		const b = rectOf(el);
		if (b.width <= 2 || b.height <= 2) continue;
		const st = styleOf(el);
		const pl = parseFloat(st.paddingLeft) + parseFloat(st.borderLeftWidth);
		if (boxed(el) && pl < 8) out.edge.push(`${label(el)} tekst ${Math.round(pl)}px od krawędzi pola (min. 8)`);
	}
	// widoczna lewa/prawa krawędź elementu: pudełko z tłem/ramką, inaczej jego treść (tekst, ikona, obraz)
	const edgeCache = new Map();
	const visEdges = (e) => {
		if (edgeCache.has(e)) return edgeCache.get(e);
		let res = null;
		if (boxed(e)) {
			const bb = rectOf(e);
			res = { l: bb.left, r: bb.right };
		} else {
			let l = Infinity, r = -Infinity;
			const w = document.createTreeWalker(e, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
			for (let n = w.nextNode(); n; n = w.nextNode()) {
				if (n.nodeType === 1) {
					if (!/^(svg|img|video|canvas|picture)$/i.test(n.tagName) && !boxed(n)) continue;
					if (!vis(n)) continue;
					const bb = rectOf(n);
					l = Math.min(l, bb.left);
					r = Math.max(r, bb.right);
				} else if (n.textContent.trim() && vis(n.parentElement)) {
					const rg = document.createRange();
					rg.selectNodeContents(n);
					for (const q of rg.getClientRects()) if (q.width > 0) { l = Math.min(l, q.left); r = Math.max(r, q.right); }
				}
			}
			// karuzela (overflow): widoczna krawędź kończy się na jej pudełku, nie na ostatniej karcie poza ekranem
			if (l !== Infinity && /hidden|auto|scroll|clip/.test(styleOf(e).overflowX)) {
				const bb = rectOf(e);
				l = Math.max(l, bb.left);
				r = Math.min(r, bb.right);
			}
			if (l !== Infinity) res = { l, r };
		}
		edgeCache.set(e, res);
		return res;
	};
	// krawędź kolumny: przycisk z napisem bez tła stoi pudełkiem na krawędzi kolumny, a jego treść jest wcięta paddingiem,
	// choć inne elementy tej kolumny zaczynają się (albo kończą) na krawędzi (podpis pod polem pliku)
	for (const el of document.querySelectorAll('button,a[href],[role=button],summary')) {
		if (!vis(el) || el.closest('[data-helix-ignore]')) continue;
		const st = styleOf(el);
		// menu nawigacji ma własny rytm (pozycje z tłem aktywnej i najechanej równe między sobą), tu go nie oceniamy
		if (st.display === 'inline' || boxed(el) || !(el.innerText || '').trim() || el.closest('nav')) continue;
		const pl = parseFloat(st.paddingLeft), pr = parseFloat(st.paddingRight);
		if (pl < 6 && pr < 6) continue;
		const b = rectOf(el);
		// treść zaczyna się dokładnie za paddingiem (wyśrodkowana treść w szerokim pasku, np. ogłoszenie, to nie wcięcie)
		const ce = visEdges(el);
		if (!ce) continue;
		// wcięcie 6-24 px = padding przycisku; większy odstęp to miejsce zarezerwowane (np. krzyżyk paska ogłoszeń)
		const padL = ce.l - b.left >= 6 && ce.l - b.left <= 24 && ce.l - (b.left + pl + parseFloat(st.borderLeftWidth)) <= 1;
		const padR = b.right - ce.r >= 6 && b.right - ce.r <= 24 && b.right - pr - parseFloat(st.borderRightWidth) - ce.r <= 1;
		if (!padL && !padR) continue;
		for (let a = el.parentElement, depth = 0; a && a !== document.body && depth < 8; a = a.parentElement, depth++) {
			const kids = [...a.children].filter((k) => vis(k) && !/absolute|fixed/.test(styleOf(k).position));
			if (kids.length < 2) continue;
			const rects = kids.map((k) => rectOf(k));
			if (!rects.every((q, i) => i === 0 || q.top >= rects[i - 1].bottom - 1)) continue; // rząd: szukaj kolumny wyżej
			// kolumna sama jest pudełkiem z tłem/ramką (karta na telefonie): wcięcie treści liczy się od karty, a pełnej
			// szerokości rząd w środku (pasek akcji z kreskami) to wzór karty, nie przycisk na krawędzi kolumny
			if (boxed(a)) break;
			const as = styleOf(a), ab = rectOf(a);
			const cl = ab.left + parseFloat(as.borderLeftWidth) + parseFloat(as.paddingLeft);
			const cr = ab.right - parseFloat(as.borderRightWidth) - parseFloat(as.paddingRight);
			const mine = kids.find((k) => k.contains(el));
			if (!mine) break; // przycisk w warstwie absolute/fixed: nie stoi w kolumnie
			// wiersz listy takich samych wierszy (menu boczne: linki i przełącznik z klasą .row) ma padding wzorca
			// listy, nie jest przyciskiem na krawędzi kolumny (inaczej alarm na każdym ekranie przy 1440)
			if (a.matches('nav, .nav, [role=navigation]') || (mine.className && kids.filter((k) => k.className === mine.className).length >= 3)) break;
			// przycisk w pudełku z tłem (np. jedyny wiersz karty ustawień): wcięcie treści liczy się od pudełka, nie od kolumny
			if (boxed(mine)) break;
			// rodzeństwo tego samego rodzaju (np. aktywna pozycja menu z tłem) ma treść na tej samej osi co reszta pozycji
			// ten sam rodzaj = ten sam tag albo ta sama pierwsza klasa (wiersz-przycisk i wiersz-div z kontrolką w jednej karcie)
			const others = kids.filter((k) => k !== mine && k.tagName !== mine.tagName && !(k.classList[0] && k.classList[0] === mine.classList[0]));
			// treść innego bloku stoi na tej samej osi co treść przycisku (np. logo na osi ikon menu obok aktywnej pigułki): równo
			const contentEdges = (k) => { let l = Infinity, r = -Infinity; const w = document.createTreeWalker(k, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT); for (let n = w.nextNode(); n; n = w.nextNode()) { if (n.nodeType === 1) { if (!/^(svg|img)$/i.test(n.tagName) || !vis(n)) continue; const bb = rectOf(n); l = Math.min(l, bb.left); r = Math.max(r, bb.right); } else if (n.textContent.trim() && vis(n.parentElement)) { const rg = document.createRange(); rg.selectNodeContents(n); for (const q of rg.getClientRects()) if (q.width > 0) { l = Math.min(l, q.left); r = Math.max(r, q.right); } } } return l === Infinity ? null : { l, r }; };
			const onAxis = (side) => others.some((k) => { const c2 = contentEdges(k); return c2 && Math.abs(c2[side] - ce[side]) <= 2; });
			if (padL && !onAxis('l') && Math.abs(b.left - cl) <= 1 && others.some((k) => { const e2 = visEdges(k); return e2 && Math.abs(e2.l - cl) <= 2; }))
				out.axis.push(`${label(el)}: treść ${Math.round(pl)}px od lewej krawędzi kolumny, reszta kolumny zaczyna się na krawędzi (przycisk bez tła)`);
			if (padR && !onAxis('r') && Math.abs(b.right - cr) <= 1 && others.some((k) => { const e2 = visEdges(k); return e2 && Math.abs(e2.r - cr) <= 2; }))
				out.axis.push(`${label(el)}: treść ${Math.round(pr)}px od prawej krawędzi kolumny, reszta kolumny kończy się na krawędzi (przycisk bez tła)`);
			break;
		}
	}
	// oś tytułu: h1-h3 i akcje obok w jednym rzędzie mają wspólny środek (pierwsza linia tytułu, ±3 px)
	for (const h of document.querySelectorAll('h1,h2,h3')) {
		if (!vis(h) || h.closest('[data-helix-ignore]')) continue;
		const rg = document.createRange();
		rg.selectNodeContents(h);
		const l1 = [...rg.getClientRects()].find((q) => q.width > 0 && q.height > 0);
		const hb = rectOf(h);
		if (!l1 || hb.width <= 2 || hb.height <= 2) continue; // .sr-only
		const hc = l1.top + l1.height / 2;
		for (let a = h.parentElement, depth = 0; a && a !== document.body && depth < 3; a = a.parentElement, depth++) {
			// rząd nagłówka (do 120 px wysokości), nie układ strony z kolumnami, w których przypadkiem stoi przycisk na tej wysokości
			if (!/flex|grid/.test(styleOf(a).display) || rectOf(a).height > 120) continue;
			const mine = [...a.children].find((k) => k.contains(h));
			const ctrls = [...a.children]
				.filter((k) => k !== mine && vis(k))
				.flatMap((k) => (k.matches('button,a[href],[role=button],select') ? [k] : [...k.querySelectorAll('button,a[href],[role=button],select')]))
				.filter((c) => vis(c) && styleOf(c).display !== 'inline' && !c.closest('[data-helix-ignore]'));
			const same = ctrls.filter((c) => { const bb = rectOf(c); return bb.top < l1.bottom && bb.bottom > l1.top && bb.height <= 64; });
			if (!same.length) continue;
			// oś = środek pierwszej linii tytułu ALBO całego tytułu (dwuliniowy tytuł z przyciskiem na środku bloku), jak kolumna wiodąca
			const hbc = hb.top + hb.height / 2;
			const d = Math.max(...same.map((c) => { const bb = rectOf(c); const cc = bb.top + bb.height / 2; return Math.min(Math.abs(cc - hc), Math.abs(cc - hbc)); }));
			if (d > 3) out.axis.push(`${label(h)} i akcje obok (${label(same[0])}) ${Math.round(d)}px od wspólnej osi`);
			break;
		}
	}
	// odstępy: pionowa przerwa między pudełkami z tłem/ramką, jedno pod drugim w tej samej kolumnie, z drabinki (±1)
	if (space.length) {
		for (const a of document.querySelectorAll('body *')) {
			if (a.childElementCount < 2 || !vis(a) || a.closest('[data-helix-ignore]')) continue;
			const kids = [...a.children].filter((k) => vis(k) && !/absolute|fixed/.test(styleOf(k).position));
			for (let i = 1; i < kids.length; i++) {
				const p0 = kids[i - 1], q0 = kids[i];
				if (!boxed(p0) || !boxed(q0)) continue;
				const pb = rectOf(p0), qb = rectOf(q0);
				if (qb.top < pb.bottom - 1 || qb.left >= pb.right || qb.right <= pb.left) continue;
				const g = qb.top - pb.bottom;
				if (g <= 1.5 || g > 96) continue;
				if (!space.some((v) => Math.abs(v - g) <= 1)) out.gap.push(`${Math.round(g)}px między ${label(p0)} a ${label(q0)}`);
			}
		}
	}
	// tekst na tekście: kolumna ściśnięta do zera albo liczba wjeżdżająca na sąsiednią komórkę (np. „123 456,78 zł” na „13”,
	// nagłówki „Numer” i „Wystawiona” na sobie). Prostokąty przycinane do przodków z overflow (wielokropek to nie nachodzenie),
	// pomijane warstwy fixed/sticky (dolne menu nad treścią).
	{
		const clipCache = new Map();
		const clipOf = (e) => {
			if (clipCache.has(e)) return clipCache.get(e);
			let c = { l: -1e9, r: 1e9, t: -1e9, b: 1e9 }, fixed = false;
			for (let a = e; a && a !== document.documentElement; a = a.parentElement) {
				const st = styleOf(a);
				if (/fixed|sticky/.test(st.position)) fixed = true;
				// także sam element: przycięta nazwa (line-clamp, wielokropek) chowa własne dalsze linie
				if (/hidden|clip|auto|scroll/.test(st.overflowX + st.overflowY)) {
					const ab = rectOf(a);
					c = { l: Math.max(c.l, ab.left), r: Math.min(c.r, ab.right), t: Math.max(c.t, ab.top), b: Math.min(c.b, ab.bottom) };
				}
			}
			const res = fixed ? null : c;
			clipCache.set(e, res);
			return res;
		};
		const boxes = [];
		const tw = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
		while (tw.nextNode()) {
			const tn = tw.currentNode, el = tn.parentElement;
			if (!el || !tn.textContent.trim() || !vis(el) || el.closest('[data-helix-ignore]') || +styleOf(el).opacity < 0.1) continue;
			const c = clipOf(el);
			if (!c) continue;
			const rg = document.createRange();
			rg.selectNodeContents(tn);
			for (const q of rg.getClientRects()) {
				const bx = { el, l: Math.max(q.left, c.l), r: Math.min(q.right, c.r), t: Math.max(q.top, c.t), b: Math.min(q.bottom, c.b) };
				if (bx.r - bx.l > 1 && bx.b - bx.t > 1) boxes.push(bx);
			}
		}
		boxes.sort((x, y) => x.t - y.t);
		// jeden wpis na parę rodzajów elementów (tag + klasy), z liczbą wystąpień i przykładem: 90 wierszy tabeli = 1 problem
		const kind = (e) => e.tagName.toLowerCase() + (typeof e.className === 'string' && e.className.trim() ? '.' + e.className.trim().split(/\s+/).slice(0, 2).join('.') : '');
		const pairs = new Map();
		for (let i = 0; i < boxes.length; i++) {
			const a = boxes[i];
			for (let j = i + 1; j < boxes.length && boxes[j].t < a.b - 2; j++) {
				const c = boxes[j];
				if (c.el === a.el || a.el.contains(c.el) || c.el.contains(a.el)) continue;
				if (Math.min(a.r, c.r) - Math.max(a.l, c.l) > 2 && Math.min(a.b, c.b) - Math.max(a.t, c.t) > 2) {
					const key = kind(a.el) + ' × ' + kind(c.el);
					const g = pairs.get(key);
					if (g) g.n++;
					else pairs.set(key, { n: 1, ex: label(a.el) + ' × ' + label(c.el) });
				}
			}
		}
		for (const [, g] of pairs) out.clip.push(`tekst na tekście${g.n > 1 ? ` (×${g.n})` : ''}: ${g.ex}`);
	}
	// prawie równo: w kolumnie (dzieci jedno pod drugim) tekst dwóch bloków zaczyna się 3-12 px od siebie. Większa różnica to
	// zamierzone wcięcie (poziom drzewa, ikona), mniejsza niż 3 to zaokrąglenie. Liczy się tylko tekst poza pudełkami z tłem
	// (napis w pigułce czy na aktywnej pozycji jest wcięty jej paddingiem) i nie wyśrodkowany.
	{
		const freeText = (root) => {
			const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
			for (let tn = w.nextNode(); tn; tn = w.nextNode()) {
				const e = tn.parentElement;
				// wykres (role="img"): etykiety osi stoją pod słupkami, nie w kolumnie tekstu
				if (!tn.textContent.trim() || !vis(e) || styleOf(e).textAlign === 'center' || e.closest('[role="img"]')) continue;
				let boxedIn = false;
				for (let a = e; a && a !== root.parentElement; a = a.parentElement) if (boxed(a) || /absolute|fixed/.test(styleOf(a).position)) { boxedIn = true; break; }
				if (boxedIn) continue;
				const rg = document.createRange();
				rg.selectNodeContents(tn);
				const q = [...rg.getClientRects()].find((x) => x.width > 0);
				return q ? { l: q.left, r: q.right } : null;
			}
			return null;
		};
		const seen = new Set();
		for (const a of document.querySelectorAll('body *')) {
			if (a.childElementCount < 2 || a.childElementCount > 40 || !vis(a) || a.closest('[data-helix-ignore]')) continue;
			// elementy w linii tekstu (span z liczbą w zawijanym zdaniu) nie są blokami kolumny, nawet gdy wypadły w kolejnych liniach
			const kids = [...a.children].filter((k) => vis(k) && !/absolute|fixed/.test(styleOf(k).position) && styleOf(k).display !== 'inline');
			if (kids.length < 2) continue;
			const rects = kids.map((k) => rectOf(k));
			if (!rects.every((q, i) => i === 0 || q.top >= rects[i - 1].bottom - 1)) continue;
			const starts = kids.map((k) => ({ k, x: freeText(k) })).filter((o) => o.x != null);
			for (let i = 0; i < starts.length; i++)
				for (let j = i + 1; j < starts.length; j++) {
					const a = starts[i].x, b = starts[j].x;
					const d = Math.abs(a.l - b.l);
					// wspólna prawa krawędź (kwota i „z 100 000 zł” pod nią) albo wspólny środek (kafelek dzień/godzina)
					// to wyrównanie na innej osi: różnica lewych krawędzi niczego wtedy nie mówi
					const other = Math.abs(a.r - b.r) <= 2.5 || Math.abs((a.l + a.r) - (b.l + b.r)) / 2 <= 2.5;
					if (d > 2.5 && d <= 12 && !other) {
						const key = label(starts[i].k) + ' / ' + label(starts[j].k);
						if (seen.has(key)) continue;
						seen.add(key);
						out.axis.push(`prawie równo: tekst ${label(starts[j].k)} zaczyna się ${Math.round(d)}px obok tekstu ${label(starts[i].k)} w tej samej kolumnie`);
					}
				}
		}
	}
	const bottomNav = (el) => {
		if (!el.closest('nav, [role="navigation"]')) return false;
		// pasek przyklejony do dołu albo pływająca pigułka nad dołem (panel firmy: 16 px od krawędzi)
		for (let a = el; a; a = a.parentElement)
			if (styleOf(a).position === 'fixed' && rectOf(a).top >= innerHeight / 2) return true;
		return false;
	};
	const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
	const seen = new Set();
	while (walker.nextNode()) {
		const el = walker.currentNode.parentElement;
		if (!el || seen.has(el) || !walker.currentNode.textContent.trim() || !vis(el) || el.closest('[data-helix-ignore]')) continue;
		seen.add(el);
		// tekst tylko dla czytników ekranu (1×1 px, clip) nie jest widoczny: ani drabinka, ani ucięcie
		{ const q = rectOf(el); if (q.width <= 1 && q.height <= 1) continue; }
		const s = styleOf(el);
		const fs = Math.round(parseFloat(s.fontSize) * 10) / 10;
		if (!ladder.includes(fs) && !(fs >= 9 && fs <= 11 && bottomNav(el))) (out.font[fs] ||= []).push(label(el));
		// ucięty tekst: liczba/telefon/kwota ucięta = błędna informacja (bloker); ucięta nazwa = ostrzeżenie
		const txt = el.innerText || '';
		if (/hidden|clip/.test(s.overflowX + s.overflow) && el.scrollWidth > el.clientWidth + 1)
			// liczba = cyfry + najwyżej 4 litery (zł, m², szt); nazwa z cyfrą („Dostawa do 25 km”) = ostrzeżenie
			(/\d/.test(txt) && (txt.match(/\p{L}/gu) || []).length <= 4 ? out.clip : out.warn).push(`ucięte ${label(el)}`);
		// liczba złamana na 2+ linie = błędna informacja. Sprawdzamy SAMĄ liczbę (cyfry z separatorami
		// tysięcy/dziesiętnymi/czasu/wymiarów), nie całe zdanie: „Rozmowa wychodząca 12345•••678”
		// może zawinąć się między słowami, ale „12 345,67” nie może pęknąć w środku.
		// Tekst rozbity na kilka węzłów (np. „12 345<small>,67 zł</small>”) sprawdzamy też jako całość elementu.
		const lineCount = (rg) => {
			// linie = skupiska prostokątów (mniejsze „,48 zł” obok liczby to ta sama linia)
			const rs = [...rg.getClientRects()].filter((q) => q.width > 1 && q.height > 1).sort((x, y) => x.top - y.top);
			let lines = rs.length ? 1 : 0;
			for (let i = 1; i < rs.length; i++) if (rs[i].top >= rs[i - 1].bottom - 2) lines++;
			return lines;
		};
		// bez myślnika: zakres „13-14 lipca” w treści może się złamać jak zwykły tekst
		// spacja należy do liczby tylko jako separator tysięcy („1 249 345”); „01.01.2026 12:00” = data i godzina osobno
		const NUM = /\d(?:[\d.,:×•]|[ \u00a0\u202f](?=\d{3}(?![\d:])))*/g;
		for (const tn of el.childNodes) {
			if (tn.nodeType !== 3) continue;
			for (const m of tn.textContent.matchAll(NUM)) {
				if (m[0].length < 2) continue;
				const rg = document.createRange();
				rg.setStart(tn, m.index);
				rg.setEnd(tn, m.index + m[0].length);
				if (lineCount(rg) > 1) out.clip.push(`liczba złamana „${m[0]}”: ${label(el)}`);
			}
		}
		if (el.childElementCount && /^[\d\s\u00a0\u202f.,:×\-–zł mhin]+$/.test(txt.trim()) && /\d/.test(txt)) {
			const rg = document.createRange();
			rg.selectNodeContents(el);
			if (lineCount(rg) > 1) out.clip.push(`złamana w ${lineCount(rg)} linie: ${label(el)}`);
		}
		// tekst wystający poza najbliższą powierzchnię (kafel/pole z tłem albo zaokrągleniem)
		const r0 = rectOf(el);
		for (let a = el.parentElement; a && a !== document.body; a = a.parentElement) {
			const as = styleOf(a);
			if (/auto|scroll/.test(as.overflowX)) break; // przewijany pasek: wystawanie jest zamierzone
			const bg = lum(as.backgroundColor);
			if ((bg && bg.a > 0.5) || parseFloat(as.borderTopLeftRadius) > 0) {
				const ra = rectOf(a);
				if (r0.right > ra.right + 1 || r0.left < ra.left - 1) out.clip.push(`wystaje z ${a.tagName.toLowerCase()}.${(a.getAttribute('class') || '').split(' ')[0]}: ${label(el)}`);
				break;
			}
		}
		if (el.closest(':disabled,[aria-disabled="true"]')) continue;
		const ratio = textContrast(el);
		if (ratio === null) { out.warn.push(`kontrast wymaga oceny zrzutu: ${label(el)}`); continue; }
		const big = fs >= 24 || (fs >= 18.666 && +s.fontWeight >= 700);
		if (ratio < (big ? 3 : 4.5)) out.contrast.push(`${label(el)} ${ratio.toFixed(2)}:1 @${fs}px`);
	}
	return out;
}
