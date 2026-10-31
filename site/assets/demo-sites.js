/*
                   __    __        _____
   ____ ___  _____/ /_  / /_______/ ___/
  / __ `__ \/ ___/ __ \/ //_/ ___/ __ \
 / / / / / (__  ) / / / ,< / /  / /_/ /
/_/ /_/ /_/____/_/ /_/_/|_/_/   \____/

 file:    site/assets/demo-sites.js
 author:  mshkr6
 created: 2026-10-31
 about:   Демо-сайты кабинета из одного снимка эксперимента. Каждому сайту достаются свои посещения:
          обучение + контрольные + выбранные сценарии атак, поэтому изменения, риск и 152-ФЗ у него
          настоящие, посчитанные детектором. Адреса стенда заменены на домены сайтов.
          Решения владельца в демо живут в sessionStorage — их видят и кабинет, и пульт сайта.
          Состояние датчика (связь, покрытие) — демо-значения: в датчике этого пока нет.
*/
(function () {
  var BASE = window.__DOZOR_SNAPSHOT__;
  if (!BASE) return;

  var EVIL = 'static-cdn.example';
  // scenarios — id из experiment.results; learn — сколько посещений обучения уже собрано
  var SITES = [
    { id: 'uyut-remont', host: 'uyut-remont.ru', scenarios: 'all', experiment: true,
      sensor: { ageSec: 4, coverage: 0.99 } },
    { id: 'clinic-dent', host: 'clinic-dent.ru', scenarios: ['foreign-analytics'],
      sensor: { ageSec: 9, coverage: 0.98 } },
    { id: 'flowers-don', host: 'flowers-don.ru', scenarios: ['legit-widget'],
      sensor: { ageSec: 7, coverage: 0.64, gap: '/checkout' } },
    { id: 'mshkr6', host: 'mshkr6.ru', scenarios: [],
      sensor: { ageSec: 2, coverage: 1 } },
    { id: 'shop-new', host: 'shop-new.ru', scenarios: [], learn: 9,
      sensor: { ageSec: 31, coverage: 1 } }
  ];
  var LEARN_TARGET = 15;

  // заголовок изменения — как chgTitle() в пульте, чтобы список и пульт говорили одно и то же
  function scriptName(k) {
    if (k === 'page') return 'страница сайта';
    try { var u = new URL(k); return u.pathname.split('/').pop() || u.host; } catch (e) { return k; }
  }
  function changeTitle(c) {
    var T = c.items.map(function (i) { return i.type; }), it = c.items[0];
    var has = function (t) { return T.indexOf(t) >= 0; };
    if (c.kind === 'law') {
      var nm = it.service && it.service !== c.subject ? it.service : c.subject;
      return T.some(function (t) { return /^PRIVACY_TRANSBORDER/.test(t); }) ? 'Персональные данные уходят: ' + nm : 'Ресурс с иностранного сервера: ' + nm;
    }
    if (c.kind === 'redirect') return 'Внедрённый редирект на странице ' + c.subject;
    if (c.kind === 'res') {
      var rn = it.service && it.service !== c.subject && it.service !== 'сторонний сервер' ? it.service : c.subject;
      return it.jurisdiction === 'RU' || it.jurisdiction === 'self' ? 'Новый внешний ресурс: ' + rn : 'Загрузка с постороннего сервера: ' + rn;
    }
    if (c.subject === 'page' && has('IFRAME_INJECTED')) return 'В страницу вставлен чужой iframe';
    if (/^inline/.test(c.subject)) return 'Новый встроенный скрипт на странице';
    if (has('SCRIPT_MODIFIED')) return 'Подменён скрипт ' + scriptName(c.subject);
    if (has('NEW_SCRIPT')) return 'Новый скрипт ' + scriptName(c.subject);
    return scriptName(c.subject) + ' ведёт себя иначе';
  }
  var sevOf = function (r) { return r >= 0.8 ? 'critical' : r >= 0.6 ? 'high' : r >= 0.35 ? 'medium' : r > 0 ? 'low' : 'ok'; };
  var uniq = function (a) { return a.filter(function (x, i) { return a.indexOf(x) === i; }); };
  var cache = {};

  function rename(site) {
    var json = JSON.stringify(BASE).split('127.0.0.1:4100').join(site.host).split('127.0.0.1:4200').join(EVIL);
    return JSON.parse(json);
  }

  function build(site) {
    var S = rename(site), E = S.experiment;
    var learn = S.sessions.filter(function (x) { return x.mode === 'learn'; })
      .sort(function (a, b) { return a.first - b.first; }).slice(0, site.learn || LEARN_TARGET);
    var keep = {};
    learn.forEach(function (x) { keep[x.id] = 1; });
    if (!site.learn) {
      E.cleanSessions.forEach(function (id) { keep[id] = 1; });
      E.results.forEach(function (r) { if (site.scenarios === 'all' || site.scenarios.indexOf(r.id) >= 0) keep[r.session] = 1; });
    }
    var has = function (id) { return keep[id] === 1; };

    var sessions = S.sessions.filter(function (x) { return has(x.id); });
    var anomalies = S.anomalies.filter(function (a) { return has(a.session); });
    var events = S.events.filter(function (e) { return has(e.session); });
    var changes = S.changes.map(function (c) {
      var items = c.items.filter(function (i) { return has(i.session); });
      if (!items.length) return null;
      var risk = Math.max.apply(null, items.map(function (i) { return i.risk; }));
      var ts = items.map(function (i) { return i.t; });
      return Object.assign({}, c, {
        items: items,
        sessions: c.sessions.filter(has),
        pages: uniq(items.map(function (i) { return i.page; })),
        first: Math.min.apply(null, ts), last: Math.max.apply(null, ts),
        maxRisk: risk, severity: sevOf(risk),
        interpreters: uniq(items.map(function (i) { return i.interpreter; })),
        count: items.reduce(function (n, i) { return n + (i.n || 1); }, 0)
      });
    }).filter(Boolean);

    var monitor = sessions.filter(function (x) { return x.mode === 'monitor'; });
    var share = sessions.length / S.sessions.length;
    var bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    anomalies.forEach(function (a) { if (a.severity in bySev) bySev[a.severity]++; });
    var st = S.summary.stats;

    var summary = Object.assign({}, S.summary, {
      id: site.id, hosts: [site.host],
      mode: site.learn ? 'learn' : 'monitor',
      stats: Object.assign({}, st, {
        events: Math.round(st.events * share),
        sessionsMonitor: monitor.length, monitorSessions: monitor.length,
        monitorSessionsClean: monitor.filter(function (x) { return !anomalies.some(function (a) { return a.session === x.id; }); }).length,
        learnSessions: learn.length, learnEvents: Math.round(st.learnEvents * learn.length / LEARN_TARGET),
        heartbeatAgeSec: site.sensor.ageSec, coverage: site.sensor.coverage, coverageGap: site.sensor.gap || null,
        automationSessions: sessions.length
      }),
      anomaliesBySeverity: bySev,
      changes: { total: changes.length, open: changes.length, incidents: 0 }
    });

    var snap = { date: S.date, summary: summary, anomalies: anomalies, changes: changes, sessions: sessions, events: events, demoSite: site };
    if (site.experiment) snap.experiment = E;
    return snap;
  }

  function snap(id) {
    var site = SITES.filter(function (s) { return s.id === id; })[0] || SITES[0];
    return cache[site.id] || (cache[site.id] = build(site));
  }

  // решения владельца в демо: { ключ изменения: статус }
  function decisions(id) {
    try { return JSON.parse(sessionStorage.getItem('argus-dec:' + id) || '{}'); } catch (e) { return {}; }
  }
  function saveDecisions(id, d) {
    try { sessionStorage.setItem('argus-dec:' + id, JSON.stringify(d)); } catch (e) {}
  }

  // карточка сайта для кабинета: статус, риск, главное изменение, датчик
  function card(id) {
    var S = snap(id), s = S.summary, dec = decisions(s.id);
    var open = S.changes.filter(function (c) { return !dec[c.key]; });
    var sec = open.filter(function (c) { return c.interpreters.indexOf('security') >= 0; });
    var law = open.filter(function (c) { return c.interpreters.indexOf('privacy') >= 0; });
    var incidents = S.changes.filter(function (c) { return dec[c.key] === 'incident'; }).length;
    // наибольший риск посещения — как в пульте: max(риск посещения, риск его находок)
    var maxRisk = S.sessions.filter(function (x) { return x.mode === 'monitor'; }).reduce(function (m, x) {
      return S.anomalies.reduce(function (r, a) { return a.session === x.id ? Math.max(r, a.risk) : r; }, Math.max(m, x.risk || 0));
    }, 0);
    var sensorWeak = s.stats.coverage < 0.9 || s.stats.heartbeatAgeSec > 60;
    var status = s.mode === 'learn' ? 'learn'
      : sec.some(function (c) { return c.maxRisk >= 0.6; }) || incidents ? 'bad'
      : law.length ? 'law'
      : open.length || sensorWeak ? 'warn' : 'ok';
    var top = open[0];
    return {
      id: s.id, host: s.hosts[0], mode: s.mode, status: status, risk: maxRisk,
      open: open.length, openLaw: law.length, incidents: incidents,
      top: top ? { title: changeTitle(top), severity: top.severity } : null,
      learn: { done: s.stats.learnSessions, target: LEARN_TARGET },
      monitor: s.stats.monitorSessions,
      sensor: { ageSec: s.stats.heartbeatAgeSec, coverage: s.stats.coverage, gap: s.stats.coverageGap, weak: sensorWeak }
    };
  }

  window.ARGUS_DEMO = {
    ids: SITES.map(function (s) { return s.id; }),
    snap: snap,
    list: function () { return SITES.map(function (s) { return snap(s.id).summary; }); },
    card: card,
    decisions: decisions,
    saveDecisions: saveDecisions
  };
})();
