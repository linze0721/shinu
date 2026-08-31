/* shinu console — no frameworks, no build step.
   One script drives both pages; <body data-page="auth|console"> picks the path.
   Every string interpolated into HTML goes through esc(): space names, notes,
   emails and tokens are all user-controlled. */
'use strict';
(function () {
  /* ================= shared helpers ================= */

  function $(selector) {
    return document.querySelector(selector);
  }

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (ch) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      }[ch];
    });
  }

  function ApiError(message, status) {
    Error.call(this, message);
    this.message = message;
    this.status = status;
  }
  ApiError.prototype = Object.create(Error.prototype);

  /* credentials:'same-origin' is what carries the shinu_session cookie the
     browser got at login. */
  function api(method, path, body) {
    return fetch(path, {
      method: method,
      credentials: 'same-origin',
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    }).then(null, function () {
      throw new ApiError('cannot reach the shinu daemon', 0);
    }).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try {
            data = JSON.parse(text);
          } catch (_) {
            /* error bodies are always JSON; a non-JSON 2xx is treated as empty */
          }
        }
        if (!res.ok) {
          var message =
            data && typeof data.error === 'string'
              ? data.error
              : 'request failed (HTTP ' + res.status + ')';
          throw new ApiError(message, res.status);
        }
        return data;
      });
    });
  }

  function shortId(id) {
    return id ? String(id).slice(0, 8) : null;
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    var units = ['KiB', 'MiB', 'GiB', 'TiB'];
    var v = n;
    var u = -1;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u += 1;
    }
    return (v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + units[u];
  }

  function fmtMib(mib) {
    return fmtBytes((Number(mib) || 0) * 1024 * 1024);
  }

  // Capacity integrated over time, so it scales past MiB into GiB but never
  // becomes a plain byte count: 1 GiB held for one hour and 1 MiB held for
  // 1024 hours are the same figure.
  function fmtMibHours(mibHours) {
    var v = Math.max(0, Number(mibHours) || 0);
    if (v < 1) return v.toFixed(2) + ' MiB\u00b7h';
    if (v < 1024) return (v < 10 ? v.toFixed(1) : Math.round(v)) + ' MiB\u00b7h';
    var g = v / 1024;
    return (g < 10 ? g.toFixed(2) : g.toFixed(1)) + ' GiB\u00b7h';
  }

  function fmtDuration(totalSeconds) {
    var s = Math.max(0, Number(totalSeconds) || 0);
    if (s < 60) return s + ' s';
    if (s < 3600) return Math.round(s / 60) + ' min';
    var h = s / 3600;
    return (h >= 10 ? Math.round(h) : h.toFixed(1)) + ' h';
  }

  function timeAgo(iso) {
    var t = new Date(iso);
    if (isNaN(t.getTime())) return String(iso || '');
    var s = Math.floor((Date.now() - t.getTime()) / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return s + ' s ago';
    var m = Math.floor(s / 60);
    if (m < 60) return m + ' min ago';
    var h = Math.floor(m / 60);
    if (h < 24) return h + ' h ago';
    var d = Math.floor(h / 24);
    if (d < 30) return d + ' d ago';
    return t.toISOString().slice(0, 10);
  }

  function absTime(iso) {
    var t = new Date(iso);
    return isNaN(t.getTime()) ? String(iso || '') : t.toLocaleString();
  }

  /* Future-relative counterpart to timeAgo, for lease deadlines. */
  function timeUntil(iso) {
    var t = new Date(iso);
    if (isNaN(t.getTime())) return String(iso || '');
    var s = Math.ceil((t.getTime() - Date.now()) / 1000);
    if (s < 60) return 'in ' + Math.max(s, 1) + ' s';
    var m = Math.floor(s / 60);
    if (m < 60) return 'in ' + m + ' min';
    var h = Math.floor(m / 60);
    if (h < 24) return 'in ' + h + ' h';
    return 'in ' + Math.floor(h / 24) + ' d';
  }

  /* expires_at is RFC3339 or null: never / in <span> / expired. The full
     timestamp rides the title, matching the Created column. */
  function expiryCell(iso) {
    if (!iso) return { text: 'never', title: '', cls: '' };
    var t = new Date(iso);
    if (isNaN(t.getTime())) return { text: String(iso), title: '', cls: '' };
    if (t.getTime() <= Date.now()) {
      return { text: 'expired', title: absTime(iso), cls: ' expired' };
    }
    return { text: timeUntil(iso), title: absTime(iso), cls: '' };
  }

  /* Copy-to-clipboard with button feedback. The async Clipboard API needs a
     secure context; plain http installs fall back to selection-copy. */
  function copyText(text, btn) {
    var label = btn.textContent;
    function done(ok) {
      btn.textContent = ok ? 'Copied' : 'Copy failed, select the text manually';
      setTimeout(function () {
        btn.textContent = label;
      }, 1600);
    }
    function legacyCopy() {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try {
        ok = document.execCommand('copy');
      } catch (_) {
        ok = false;
      }
      ta.remove();
      done(ok);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        done(true);
      }, legacyCopy);
    } else {
      legacyCopy();
    }
  }

  /* ================= notices ================= */

  /* Every remaining notice is an error: the console performs no writes, and a
     failed read stays on screen until dismissed. */
  function notify(message) {
    var area = $('#notice-area');
    if (!area) return;
    for (var i = 0; i < area.children.length; i += 1) {
      if (area.children[i].getAttribute('data-msg') === message) return;
    }
    var div = document.createElement('div');
    div.className = 'notice error';
    div.setAttribute('data-msg', message);
    var span = document.createElement('span');
    span.className = 'notice-msg';
    span.textContent = message;
    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'notice-close';
    close.setAttribute('aria-label', 'Dismiss');
    close.textContent = '×';
    close.addEventListener('click', function () {
      div.remove();
    });
    div.appendChild(span);
    div.appendChild(close);
    area.appendChild(div);
  }

  /* ================= auth page ================= */

  function initAuth() {
    var form = $('#auth-form');
    var email = $('#email');
    var password = $('#password');
    var hint = $('#password-hint');
    var errBox = $('#form-error');
    var submit = $('#submit-btn');
    var tabs = { login: $('#tab-login'), register: $('#tab-register') };
    var mode = /register/.test(location.pathname) ? 'register' : 'login';

    function showError(message) {
      errBox.textContent = message;
      errBox.hidden = false;
    }

    function setMode(next) {
      mode = next;
      var registering = mode === 'register';
      Object.keys(tabs).forEach(function (key) {
        tabs[key].classList.toggle('active', key === mode);
        tabs[key].setAttribute('aria-selected', String(key === mode));
      });
      submit.textContent = registering ? 'Create account' : 'Log in';
      password.autocomplete = registering ? 'new-password' : 'current-password';
      hint.hidden = !registering;
      errBox.hidden = true;
      document.title = registering ? 'shinu: register' : 'shinu: log in';
      /* Keep the URL in sync so a refresh keeps the mode. The History API
         throws on file:// previews, hence the protocol guard. */
      if (location.protocol.indexOf('http') === 0) {
        history.replaceState(null, '', registering ? '/register' : '/login');
      }
    }

    tabs.login.addEventListener('click', function () {
      setMode('login');
    });
    tabs.register.addEventListener('click', function () {
      setMode('register');
    });
    setMode(mode);

    /* Already signed in → straight to the console. A 401 means "stay";
       a network failure means the daemon is down — say so instead of
       leaving the page silently broken (also covers file:// previews). */
    api('GET', '/console/me').then(
      function () {
        if (location.protocol.indexOf('http') === 0) location.replace('/app');
      },
      function (err) {
        if (err.status === 0) {
          showError('Cannot reach the shinu daemon. Is it running?');
        }
      }
    );

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      errBox.hidden = true;
      var address = email.value.trim();
      var secret = password.value;
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) {
        showError('Enter a valid email address.');
        email.focus();
        return;
      }
      if (!secret) {
        showError('Enter your password.');
        password.focus();
        return;
      }
      /* The backend enforces the same minimum; checking here saves a round trip. */
      if (mode === 'register' && secret.length < 12) {
        showError('Password must be at least 12 characters.');
        password.focus();
        return;
      }
      submit.disabled = true;
      submit.textContent =
        mode === 'register' ? 'Creating account…' : 'Logging in…';
      api('POST', '/console/' + mode, { email: address, password: secret }).then(
        function () {
          if (location.protocol.indexOf('http') === 0) location.replace('/app');
        },
        function (err) {
          /* Login failures deliberately don't reveal whether the email or the
             password was wrong — show the server's wording verbatim. */
          showError(err.message);
          submit.disabled = false;
          submit.textContent = mode === 'register' ? 'Create account' : 'Log in';
        }
      );
    });
  }

  /* ================= console page ================= */

  function initConsole() {
    var state = {
      me: null,
      spaces: null, /* null = never loaded; poll errors keep stale data */
      limits: null,
      usage: null,
      tokens: null,
      selected: null,
      tab: 'log',
      log: null,
      reflog: null,
      historyError: null,
    };
    var spacesCacheKey = '';
    var headCacheKey = '';

    /* Console-flavoured api(): an expired session (401) anywhere sends the
       browser back to the login page. */
    function capi(method, path, body) {
      return api(method, path, body).then(null, function (err) {
        if (err.status === 401 && location.protocol.indexOf('http') === 0) {
          location.replace('/login');
        }
        throw err;
      });
    }

    function selectedSpace() {
      if (!state.selected || !state.spaces) return null;
      for (var i = 0; i < state.spaces.length; i += 1) {
        if (state.spaces[i].name === state.selected) return state.spaces[i];
      }
      return null;
    }

    function errorState(message, retryAction) {
      return (
        '<div class="state error"><p>' +
        esc(message) +
        '</p><button class="btn small" type="button" data-action="' +
        retryAction +
        '">Retry</button></div>'
      );
    }

    function showLoading(selector) {
      $(selector).innerHTML =
        '<div class="state"><span class="spin"></span>Loading&hellip;</div>';
    }

    /* ---------- rendering ---------- */

    function renderSpaces() {
      if (!state.spaces) return;
      var key = JSON.stringify(state.spaces) + '|' + state.selected;
      if (key === spacesCacheKey) return; /* poll with no changes: keep the DOM */
      spacesCacheKey = key;
      var list = $('#spaces-list');
      if (state.spaces.length === 0) {
        list.innerHTML =
          '<div class="state"><p>No spaces yet.</p>' +
          '<p>Create one from the CLI: <span class="mono">shinu new &lt;name&gt;</span></p></div>';
        return;
      }
      list.innerHTML =
        '<table class="data-table"><thead><tr><th>Name</th><th>State</th>' +
        '<th>HEAD</th><th>Disk</th><th>Created</th><th>Expires</th></tr></thead><tbody>' +
        state.spaces
          .map(function (s) {
            var exp = expiryCell(s.expires_at);
            return (
              '<tr class="space-row' +
              (s.name === state.selected ? ' selected' : '') +
              '" data-action="select-space" data-name="' +
              esc(s.name) +
              /* the name cell carries a real button so the row stays
                 keyboard-operable; closest('[data-action]') finds it first */
              '"><td><button type="button" class="rowlink" data-action="select-space" data-name="' +
              esc(s.name) +
              '">' +
              esc(s.name) +
              '</button></td><td>' +
              (s.running ? '<span class="green">running</span>' : 'stopped') +
              '</td><td class="mono">' +
              (s.head ? esc(shortId(s.head)) : 'none') +
              '</td><td class="mono nobr">' +
              esc(fmtBytes(s.exclusive || 0)) +
              '</td><td class="space-created nobr" title="' +
              esc(absTime(s.created_at)) +
              '">' +
              esc(timeAgo(s.created_at)) +
              '</td><td class="space-expires nobr' +
              exp.cls +
              '"' +
              (exp.title ? ' title="' + esc(exp.title) + '"' : '') +
              '>' +
              esc(exp.text) +
              '</td></tr>'
            );
          })
          .join('') +
        '</tbody></table>';
    }

    /* Lines of copyable CLI commands; data-action="copy-cmd" wires the button. */
    function cliLines(commands) {
      return commands
        .map(function (cmd) {
          var html = esc(cmd);
          return (
            '<div class="cli-line"><code>' +
            html +
            '</code><button class="btn small" type="button" data-action="copy-cmd" data-copy="' +
            html +
            '">Copy</button></div>'
          );
        })
        .join('');
    }
    /* The console is read-only: the detail head shows the space name, its
       lease state, plus the CLI commands that change it, so the path from
       seeing to doing is one copy away. */
    function renderDetailHead() {
      var s = selectedSpace();
      if (!s) return;
      var key = s.name + '|' + s.running + '|' + (s.expires_at || '');
      if (key === headCacheKey) return;
      headCacheKey = key;
      $('#detail-title').textContent = s.name;
      var exp = expiryCell(s.expires_at);
      $('#detail-expiry').innerHTML =
        'Expires: <span class="space-expires' +
        exp.cls +
        '"' +
        (exp.title ? ' title="' + esc(exp.title) + '"' : '') +
        '>' +
        esc(exp.text) +
        '</span>';
      $('#cli-box').innerHTML =
        '<p class="cli-title">Manage this space from the CLI:</p>' +
        cliLines([
          'shinu exec ' + s.name + ' -- <command>',
          'shinu commit ' + s.name + ' --note "..."',
          'shinu checkout ' + s.name + ' <commit-id>',
          s.running ? 'shinu stop ' + s.name : 'shinu start ' + s.name,
        ]);
    }

    function renderDetail() {
      var s = selectedSpace();
      $('#detail-empty').hidden = !!s;
      $('#detail-main').hidden = !s;
      if (s) {
        renderDetailHead();
        renderCommitList();
      }
    }

    function renderCommitList() {
      var s = selectedSpace();
      if (!s) return;
      if (state.historyError) {
        $('#commit-list').innerHTML = errorState(state.historyError, 'retry-history');
        return;
      }
      var rows = state.tab === 'log' ? state.log : state.reflog;
      if (!rows) {
        showLoading('#commit-list');
        return;
      }
      if (rows.length === 0) {
        $('#commit-list').innerHTML =
          state.tab === 'log'
            ? '<div class="state"><p>No commits yet.</p></div>'
            : '<div class="state"><p>The archive is empty.</p></div>';
        return;
      }
      $('#commit-list').innerHTML =
        '<table class="data-table"><thead><tr><th>Id</th><th>When</th>' +
        '<th>Note</th><th>Checkout from the CLI</th></tr></thead><tbody>' +
        rows
          .map(function (c) {
            var badges = '';
            if (c.id === s.head) badges += ' <span class="badge head">HEAD</span>';
            if (c.auto) badges += ' <span class="badge auto">auto</span>';
            /* checkout takes a full UUID; the 8-char display id won't parse */
            var checkout = 'shinu checkout ' + s.name + ' ' + c.id;
            return (
              '<tr class="commit-row"><td class="commit-id mono nobr" title="' +
              esc(c.id) +
              '">' +
              esc(shortId(c.id)) +
              badges +
              '</td><td class="commit-time nobr" title="' +
              esc(absTime(c.created_at)) +
              '">' +
              esc(timeAgo(c.created_at)) +
              '</td><td class="commit-note">' +
              esc(c.note || '') +
              '</td><td>' +
              cliLines([checkout]) +
              '</td></tr>'
            );
          })
          .join('') +
        '</tbody></table>';
    }

    /* One quota row: label, "used / limit" as text (red near the cap), and a
       hard-edged bar — solid fill, square corners, no animation. */
    function meterRow(label, used, max, fmt) {
      used = Number(used) || 0;
      max = Number(max) || 0;
      var pct =
        max > 0 ? Math.min(100, Math.round((used / max) * 100)) : used > 0 ? 100 : 0;
      var cls = pct >= 100 ? ' full' : pct >= 80 ? ' warn' : '';
      return (
        '<tr><td>' +
        esc(label) +
        '</td><td class="mono nobr' +
        (pct >= 80 ? ' red' : '') +
        '">' +
        esc(fmt(used)) +
        ' / ' +
        esc(fmt(max)) +
        '</td><td class="quota-bar-cell"><div class="meter' +
        cls +
        '"><div class="fill" style="width:' +
        pct +
        '%"></div></div></td></tr>'
      );
    }

    function renderQuota() {
      var L = state.limits;
      if (!L) return;
      $('#meters').innerHTML =
        '<table class="data-table quota-table"><thead><tr><th>Resource</th>' +
        '<th>Used / limit</th><th>Usage</th></tr></thead><tbody>' +
        meterRow('Spaces', L.used.spaces, L.max_spaces, String) +
        meterRow('Disk', L.used.disk_mib, L.max_disk_mib, fmtMib) +
        meterRow('Running VMs', L.used.running, L.max_running, String) +
        '<tr><td>API rate</td><td class="mono nobr quota-num">' +
        esc(String(L.api_per_min)) +
        ' / min</td><td></td></tr>' +
        '</tbody></table>';
      var U = state.usage;
      if (U) {
        $('#usage-line').textContent =
          U.spaces_created +
          ' spaces created · ' +
          fmtDuration(U.vm_seconds) +
          ' VM time · ' +
          fmtMibHours(U.disk_mib_hour) +
          ' disk · ' +
          U.api_calls +
          ' API calls';
      }
    }

    function renderTokens() {
      if (!state.tokens) return;
      var list = $('#tokens-list');
      if (state.tokens.length === 0) {
        list.innerHTML = '<div class="state"><p>No tokens yet.</p></div>';
        return;
      }
      list.innerHTML =
        '<table class="data-table"><thead><tr><th>Prefix</th><th>Created</th>' +
        '</tr></thead><tbody>' +
        state.tokens
          .map(function (t) {
            return (
              '<tr class="token-row"><td class="token-prefix mono" title="token hash prefix">' +
              esc(t.hash_prefix) +
              '</td><td class="token-created" title="' +
              esc(absTime(t.created_at)) +
              '">created ' +
              esc(timeAgo(t.created_at)) +
              '</td></tr>'
            );
          })
          .join('') +
        '</tbody></table>';
    }

    /* Tokens are the one thing the console still creates; show how they plug
       into the CLI. location.origin keeps the endpoint right on any host.
       file:// previews have no origin — show a placeholder instead. */
    function renderCliSetup() {
      var origin =
        location.protocol.indexOf('http') === 0
          ? location.origin
          : '<host>:<port>';
      $('#cli-setup').innerHTML =
        '<p class="cli-title">Point the CLI at this server:</p>' +
        cliLines([
          'export SHINU_ENDPOINT=' + origin,
          'export SHINU_TOKEN=<token>',
        ]);
    }

    /* ---------- data loading ---------- */

    function refreshSpaces(quiet) {
      return capi('GET', '/v1/spaces').then(
        function (data) {
          state.spaces = (data && data.spaces) || [];
          if (
            state.selected &&
            !state.spaces.some(function (sp) {
              return sp.name === state.selected;
            })
          ) {
            /* deleted elsewhere (another tab, the CLI) — drop the detail view */
            state.selected = null;
            state.log = state.reflog = null;
            renderDetail();
          }
          renderSpaces();
          renderDetailHead();
        },
        function (err) {
          if (quiet && state.spaces) {
            notify(err.message);
            return;
          }
          $('#spaces-list').innerHTML = errorState(err.message, 'retry-spaces');
        }
      );
    }

    function refreshQuota(quiet) {
      return Promise.all([capi('GET', '/v1/limits'), capi('GET', '/v1/usage')]).then(
        function (results) {
          state.limits = results[0];
          state.usage = results[1];
          renderQuota();
        },
        function (err) {
          if (quiet && state.limits) {
            notify(err.message);
            return;
          }
          $('#meters').innerHTML = errorState(err.message, 'retry-quota');
        }
      );
    }

    function refreshTokens(quiet) {
      return capi('GET', '/console/tokens').then(
        function (data) {
          state.tokens = (data && data.tokens) || [];
          renderTokens();
        },
        function (err) {
          if (quiet && state.tokens) {
            notify(err.message);
            return;
          }
          $('#tokens-list').innerHTML = errorState(err.message, 'retry-tokens');
        }
      );
    }

    function loadHistory(which) {
      var name = state.selected;
      if (!name) return Promise.resolve();
      return capi(
        'GET',
        '/v1/spaces/' + encodeURIComponent(name) + '/' + which
      ).then(
        function (data) {
          if (state.selected !== name) return;
          if (which === 'log') state.log = (data && data.commits) || [];
          else state.reflog = (data && data.entries) || [];
          state.historyError = null;
          if (which === state.tab) renderCommitList();
        },
        function (err) {
          if (state.selected !== name || which !== state.tab) return;
          state.historyError = err.message;
          renderCommitList();
        }
      );
    }

    function refreshAll() {
      refreshSpaces(false);
      refreshQuota(false);
      refreshTokens(false);
      if (state.selected) loadHistory(state.tab);
    }

    /* ---------- view switching (sidemenu) ----------
       The four panels are views: exactly one is visible at a time. Purely
       presentational — all data loading/polling runs regardless of which
       view is shown. */

    var views = {
      spaces: $('#spaces-panel'),
      commits: $('#detail-panel'),
      tokens: $('#tokens-panel'),
      quota: $('#quota-panel'),
    };
    var menuItems = document.querySelectorAll('.menu-item');

    function setView(name) {
      if (!views[name]) return;
      Object.keys(views).forEach(function (key) {
        views[key].hidden = key !== name;
      });
      for (var i = 0; i < menuItems.length; i += 1) {
        var active = menuItems[i].dataset.view === name;
        menuItems[i].classList.toggle('active', active);
        menuItems[i].setAttribute('aria-pressed', String(active));
      }
    }

    function setHistoryTab(tab) {
      $('#tab-log').classList.toggle('active', tab === 'log');
      $('#tab-log').setAttribute('aria-selected', String(tab === 'log'));
      $('#tab-reflog').classList.toggle('active', tab === 'reflog');
      $('#tab-reflog').setAttribute('aria-selected', String(tab === 'reflog'));
    }

    function selectSpace(name) {
      if (!name || name === state.selected) return;
      state.selected = name;
      state.tab = 'log';
      state.log = state.reflog = null;
      state.historyError = null;
      setHistoryTab('log');
      renderSpaces();
      renderDetail();
      /* selecting a space jumps to its save points, mirroring the old
         side-by-side layout where the detail appeared on selection */
      setView('commits');
      loadHistory('log');
    }

    function setTab(tab) {
      if (state.tab === tab) return;
      state.tab = tab;
      state.historyError = null;
      setHistoryTab(tab);
      renderCommitList();
      if (tab === 'log' && !state.log) loadHistory('log');
      if (tab === 'reflog' && !state.reflog) loadHistory('reflog');
    }

    function onNewToken() {
      var tokenBtn = $('#new-token-btn');
      tokenBtn.disabled = true;
      capi('POST', '/console/tokens', {}).then(
        function (data) {
          if (data && data.token) {
            $('#token-value').textContent = data.token;
            $('#token-reveal').hidden = false;
            $('#copy-token-btn').textContent = 'Copy';
          }
          refreshTokens(true);
        },
        function (err) {
          notify(err.message);
        }
      ).then(function () {
        tokenBtn.disabled = false;
      });
    }

    function onCopyToken() {
      copyText($('#token-value').textContent, $('#copy-token-btn'));
    }

    function onLogout() {
      /* Even if the request fails, leaving is the right move: the me-check on
         the login page bounces back only if the session is genuinely alive. */
      capi('POST', '/console/logout').then(
        function () {},
        function () {}
      ).then(function () {
        if (location.protocol.indexOf('http') === 0) location.replace('/login');
      });
    }

    var actions = {
      'select-space': function (el) {
        selectSpace(el.getAttribute('data-name'));
      },
      'copy-cmd': function (el) {
        copyText(el.getAttribute('data-copy'), el);
      },
      'retry-spaces': function () {
        showLoading('#spaces-list');
        refreshSpaces(false);
      },
      'retry-quota': function () {
        showLoading('#meters');
        refreshQuota(false);
      },
      'retry-tokens': function () {
        showLoading('#tokens-list');
        refreshTokens(false);
      },
      'retry-history': function () {
        state.historyError = null;
        if (state.tab === 'log') state.log = null;
        else state.reflog = null;
        renderCommitList();
        loadHistory(state.tab);
      },
      'retry-boot': function () {
        location.reload();
      },
    };

    document.addEventListener('click', function (ev) {
      var el = ev.target.closest('[data-action]');
      if (!el) return;
      var run = actions[el.getAttribute('data-action')];
      if (run) run(el);
    });

    for (var mi = 0; mi < menuItems.length; mi += 1) {
      menuItems[mi].addEventListener('click', function () {
        setView(this.dataset.view);
      });
    }

    $('#refresh-btn').addEventListener('click', refreshAll);
    $('#logout-btn').addEventListener('click', onLogout);
    $('#tab-log').addEventListener('click', function () {
      setTab('log');
    });
    $('#tab-reflog').addEventListener('click', function () {
      setTab('reflog');
    });
    $('#new-token-btn').addEventListener('click', onNewToken);
    $('#copy-token-btn').addEventListener('click', onCopyToken);
    $('#dismiss-token-btn').addEventListener('click', function () {
      $('#token-reveal').hidden = true;
      $('#token-value').textContent = '';
    });

    renderCliSetup();

    /* ---------- boot ---------- */

    capi('GET', '/console/me').then(
      function (me) {
        state.me = me || {};
        $('#user-email').textContent = state.me.email || '';
        $('#project-badge').textContent = state.me.project || '';
        if (state.me.project) {
          document.title = 'shinu console: ' + state.me.project;
        }
        refreshAll();
        setInterval(function () {
          if (document.hidden) return;
          refreshSpaces(true);
          refreshQuota(true);
        }, 5000);
      },
      function (err) {
        /* 401 already redirected inside capi. Anything else (daemon down,
           file:// preview) gets an explicit, retryable failure state. */
        if (err.status === 401) return;
        notify(err.message);
        $('#spaces-list').innerHTML = errorState(err.message, 'retry-boot');
        $('#meters').innerHTML = errorState(err.message, 'retry-boot');
        $('#tokens-list').innerHTML = errorState(err.message, 'retry-boot');
      }
    );
  }

  /* ================= dispatch ================= */

  var page = document.body ? document.body.getAttribute('data-page') : null;
  try {
    if (page === 'auth') initAuth();
    else if (page === 'console') initConsole();
  } catch (err) {
    /* Last-resort feedback: never leave a silent white page. */
    var div = document.createElement('div');
    div.className = 'notice error';
    div.textContent =
      'console UI failed to initialise: ' + (err && err.message ? err.message : err);
    document.body.prepend(div);
  }
})();
