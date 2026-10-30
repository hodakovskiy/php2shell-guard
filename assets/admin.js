(function () {
	'use strict';

	var btn = document.getElementById('p2s-run');
	if (!btn || typeof P2S === 'undefined') {
		return;
	}
	var out = document.getElementById('p2s-progress');

	function post(data) {
		var fd = new FormData();
		Object.keys(data).forEach(function (k) {
			fd.append(k, data[k]);
		});
		return fetch(P2S.ajax, { method: 'POST', credentials: 'same-origin', body: fd })
			.then(function (r) { return r.json(); })
			.catch(function () { return null; });
	}

	function line(text, cls) {
		var d = document.createElement('div');
		d.className = 'p2s-line ' + (cls || '');
		d.textContent = text;
		out.appendChild(d);
		return d;
	}

	async function runStep(step) {
		var offset = 0;
		var el = line(step.label + ' ...', 'run');
		for (;;) {
			var res = await post({ action: 'p2s_scan_step', nonce: P2S.nonce, step: step.id, offset: offset });
			if (!res || !res.success) {
				el.className = 'p2s-line err';
				el.textContent = step.label + ': ' + P2S.i18n.error;
				return;
			}
			if (res.data.next === null || typeof res.data.next === 'undefined') {
				break;
			}
			offset = res.data.next;
			el.textContent = step.label + ' ... ' + offset;
		}
		el.className = 'p2s-line ok';
		el.textContent = step.label + ' ✓';
	}

	btn.addEventListener('click', async function () {
		btn.disabled = true;
		out.innerHTML = '';
		for (var i = 0; i < P2S.steps.length; i++) {
			await runStep(P2S.steps[i]);
		}
		await post({ action: 'p2s_scan_step', nonce: P2S.nonce, step: 'finish' });
		line(P2S.i18n.done, 'ok');
		setTimeout(function () { window.location.reload(); }, 800);
	});
})();
