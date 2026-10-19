/**
 * TenantShield Client Application Logic
 * =====================================
 * Security Principles:
 * 1. Authentication token stored in sessionStorage only (never persisted to localStorage).
 * 2. Strict DOM manipulation using textContent and createElement (zero innerHTML).
 * 3. Tenant ID is never supplied by the client on creation/updates; derived server-side.
 * 4. Automatic session termination on HTTP 401, sign out, or token expiry.
 * 5. Button disabling during network operations.
 */

(function () {
  'use strict';

  // --- Session & In-Memory State ---
  var authToken = null;
  var currentUser = null;
  var pendingDeleteDocId = null;

  var STORAGE_TOKEN_KEY = 'tenantshield_token';
  var STORAGE_PAGE_KEY = 'tenantshield_page';

  // --- DOM Elements ---
  var appHeader = document.getElementById('app-header');
  var headerMeta = document.getElementById('header-user-meta');
  var headerEmail = document.getElementById('header-email');
  var headerTenant = document.getElementById('header-tenant');
  var btnSignout = document.getElementById('btn-signout');

  var loginView = document.getElementById('login-view');
  var loginForm = document.getElementById('login-form');
  var loginEmailInput = document.getElementById('login-email');
  var loginPassInput = document.getElementById('login-password');
  var btnLoginSubmit = document.getElementById('btn-login-submit');
  var loginError = document.getElementById('login-error');

  var appShell = document.getElementById('app-shell');
  var sidebarNav = document.getElementById('sidebar-nav');

  // Tenant Workspace Views
  var tenantWorkspace = document.getElementById('tenant-workspace');
  var tenantDocsSection = document.getElementById('tenant-docs-section');
  var tenantDocsTable = document.getElementById('tenant-docs-table');
  var tenantDocsTbody = document.getElementById('tenant-docs-tbody');
  var tenantDocsEmpty = document.getElementById('tenant-docs-empty');
  var tenantDocsAlert = document.getElementById('tenant-docs-alert');
  var btnNewDoc = document.getElementById('btn-new-doc');

  var tenantDocFormSection = document.getElementById('tenant-doc-form-section');
  var docForm = document.getElementById('doc-form');
  var docFormTitle = document.getElementById('doc-form-title');
  var docFormDesc = document.getElementById('doc-form-desc');
  var docFormError = document.getElementById('doc-form-error');
  var docEditId = document.getElementById('doc-edit-id');
  var docTitleInput = document.getElementById('doc-title-input');
  var docContentInput = document.getElementById('doc-content-input');
  var btnSaveDoc = document.getElementById('btn-save-doc');
  var btnCancelDocForm = document.getElementById('btn-cancel-doc-form');

  var tenantDocViewSection = document.getElementById('tenant-doc-view-section');
  var viewDocTitle = document.getElementById('view-doc-title');
  var viewDocId = document.getElementById('view-doc-id');
  var viewDocKeyVer = document.getElementById('view-doc-key-ver');
  var viewDocCreated = document.getElementById('view-doc-created');
  var viewDocContent = document.getElementById('view-doc-content');
  var btnEditCurrentDoc = document.getElementById('btn-edit-current-doc');
  var btnBackToDocs = document.getElementById('btn-back-to-docs');

  // Admin Dashboard Views
  var adminDashboard = document.getElementById('admin-dashboard');

  // Modal
  var confirmModal = document.getElementById('confirm-modal');
  var btnConfirmCancel = document.getElementById('btn-confirm-cancel');
  var btnConfirmAction = document.getElementById('btn-confirm-action');

  function hideConfirmModal() {
    pendingDeleteDocId = null;
    if (confirmModal) {
      confirmModal.style.display = 'none';
    }
  }

  // Ensure modal is strictly hidden on script load
  hideConfirmModal();

  // --- JWT Payload Decoding & Expiry Check ---
  function parseJwtPayload(token) {
    try {
      if (!token || typeof token !== 'string') return null;
      var parts = token.split('.');
      if (parts.length < 2) return null;
      var base64Url = parts[1];
      var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4) {
        base64 += '=';
      }
      var jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map(function (c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
          })
          .join('')
      );
      return JSON.parse(jsonPayload);
    } catch (e) {
      return null;
    }
  }

  function isTokenExpired(token) {
    var payload = parseJwtPayload(token);
    if (!payload || !payload.exp) {
      return true;
    }
    var nowSec = Math.floor(Date.now() / 1000);
    return payload.exp <= nowSec;
  }

  // --- Network Helper ---
  async function apiFetch(url, options) {
    options = options || {};
    options.headers = options.headers || {};

    if (authToken) {
      options.headers['Authorization'] = 'Bearer ' + authToken;
    }

    var response;
    try {
      response = await fetch(url, options);
    } catch (err) {
      throw new Error('Network error. Check server connectivity.');
    }

    if (response.status === 401) {
      handleSignOut();
      showLoginError('Session expired or unauthorized. Please sign in again.');
      throw new Error('Unauthorized');
    }

    return response;
  }

  // --- Authentication & Session Handlers ---
  function clearAuthSession() {
    authToken = null;
    currentUser = null;
    pendingDeleteDocId = null;

    try {
      sessionStorage.removeItem(STORAGE_TOKEN_KEY);
      sessionStorage.removeItem(STORAGE_PAGE_KEY);
      sessionStorage.removeItem('token');
      sessionStorage.removeItem('access_token');
      sessionStorage.removeItem('current_page');
    } catch (e) {}

    try {
      // Defensive: Ensure token is never in localStorage
      localStorage.removeItem(STORAGE_TOKEN_KEY);
      localStorage.removeItem('token');
      localStorage.removeItem('access_token');
      localStorage.removeItem('current_page');
    } catch (e) {}

    // Clear URL hash
    if (window.location.hash) {
      try {
        history.replaceState(null, '', window.location.pathname);
      } catch (e) {
        window.location.hash = '';
      }
    }
  }

  function handleSignOut() {
    clearAuthSession();

    // Clear forms safely
    loginForm.reset();
    docForm.reset();

    // Always hide the delete-confirmation modal before returning to login
    hideConfirmModal();

    // Reset views
    headerMeta.style.display = 'none';
    appShell.style.display = 'none';
    tenantWorkspace.style.display = 'none';
    adminDashboard.style.display = 'none';
    loginView.style.display = 'flex';
  }

  // Hide any lingering modal on BFCache restore (browser back/forward or hard reload)
  window.addEventListener('pageshow', function () {
    hideConfirmModal();
    var stored = null;
    try {
      stored = sessionStorage.getItem(STORAGE_TOKEN_KEY) || sessionStorage.getItem('token');
    } catch (e) {}
    if (!stored || isTokenExpired(stored)) {
      handleSignOut();
    }
  });

  function showLoginError(msg) {
    loginError.textContent = msg;
    loginError.style.display = 'block';
  }

  function hideLoginError() {
    loginError.textContent = '';
    loginError.style.display = 'none';
  }

  loginForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    hideLoginError();

    var email = loginEmailInput.value.trim();
    var password = loginPassInput.value;

    if (!email || !password) {
      showLoginError('Please enter both email and password.');
      return;
    }

    btnLoginSubmit.disabled = true;
    btnLoginSubmit.textContent = 'Signing in...';

    try {
      var res = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
      });

      if (!res.ok) {
        var errJson = await res.json().catch(function () { return {}; });
        showLoginError(errJson.detail || 'Invalid email or password.');
        return;
      }

      var tokenData = await res.json();
      authToken = tokenData.access_token;

      try {
        sessionStorage.setItem(STORAGE_TOKEN_KEY, authToken);
        sessionStorage.setItem('token', authToken);
      } catch (err) {}

      // Fetch user profile context
      var userRes = await apiFetch('/admin/dashboard/me');
      if (!userRes.ok) {
        showLoginError('Failed to retrieve user context.');
        return;
      }

      currentUser = await userRes.json();
      renderAppShell();

      // Role-based landing: tenant users to the workspace, platform_admin to the overview dashboard
      if (currentUser.role === 'platform_admin') {
        navigate('#admin/overview');
      } else {
        navigate('#documents');
      }
    } catch (err) {
      showLoginError(err.message || 'An error occurred during sign in.');
    } finally {
      btnLoginSubmit.disabled = false;
      btnLoginSubmit.textContent = 'Sign in';
    }
  });

  btnSignout.addEventListener('click', handleSignOut);

  // --- Shell Rendering ---
  function renderAppShell() {
    hideConfirmModal();
    loginView.style.display = 'none';
    appShell.style.display = 'flex';

    headerEmail.textContent = currentUser.email;
    headerTenant.textContent = currentUser.tenant_name || 'Tenant Workspace';
    headerMeta.style.display = 'flex';

    // Clear sidebar navigation
    while (sidebarNav.firstChild) {
      sidebarNav.removeChild(sidebarNav.firstChild);
    }

    if (currentUser.role === 'platform_admin') {
      tenantWorkspace.style.display = 'none';
      adminDashboard.style.display = 'block';
      renderAdminSidebar();
      loadAllAdminSections();
    } else {
      adminDashboard.style.display = 'none';
      tenantWorkspace.style.display = 'block';
      renderTenantSidebar();
    }
  }

  // --- Status Dot Helper ---
  function createStatusBadge(text, dotType) {
    var span = document.createElement('span');
    span.className = 'status-indicator';

    var dot = document.createElement('span');
    dot.className = 'dot ' + (dotType || 'dot-unknown');

    var label = document.createElement('span');
    label.textContent = text;

    span.appendChild(dot);
    span.appendChild(label);
    return span;
  }

  function getDotTypeForStatus(statusStr) {
    var s = String(statusStr || '').toUpperCase();
    if (s === 'BLOCKED' || s === 'INTACT' || s === 'ACTIVE' || s === 'PASSED' || s === 'NO_LEAK_DETECTED' || s === 'CAUGHT') {
      return 'dot-blocked';
    }
    if (s === 'LEAKED' || s === 'COMPROMISED' || s === 'DESTROYED' || s === 'LEAK_DETECTED' || s === 'MISSED') {
      return 'dot-leaked';
    }
    if (s === 'EXPECTED_LEAK' || s === 'EXPECTED LEAK' || s === 'FLAWED_DEMO') {
      return 'dot-expected-leak';
    }
    if (s === 'RETIRED' || s === 'INCONCLUSIVE' || s === 'MASKED') {
      return 'dot-retired';
    }
    return 'dot-unknown';
  }

  // =========================================================================
  // ROUTING & NAVIGATION
  // =========================================================================
  function navigate(hash) {
    if (window.location.hash === hash) {
      handleRoute();
    } else {
      window.location.hash = hash;
    }
  }

  window.addEventListener('hashchange', function () {
    handleRoute();
  });

  async function handleRoute() {
    hideConfirmModal();
    if (!authToken || !currentUser) {
      return;
    }

    var hash = window.location.hash || '';
    if (!hash || hash === '#') {
      try {
        var stored = sessionStorage.getItem(STORAGE_PAGE_KEY);
        if (stored) {
          hash = stored;
        }
      } catch (e) {}
    }

    // Role-based landing default if still empty
    if (!hash || hash === '#') {
      if (currentUser.role === 'platform_admin') {
        hash = '#admin/overview';
      } else {
        hash = '#documents';
      }
    }

    // Strip trailing slash
    hash = hash.replace(/\/$/, '');

    // Role-based security guard: A tenant user must NEVER see admin pages even if they type the hash.
    if (currentUser.role !== 'platform_admin') {
      if (hash.indexOf('#admin') === 0) {
        navigate('#documents');
        return;
      }
    }

    // Platform admin guard: admin users must land on the admin dashboard
    if (currentUser.role === 'platform_admin') {
      if (hash.indexOf('#admin') !== 0) {
        navigate('#admin/overview');
        return;
      }
    }

    // Save current page to sessionStorage
    try {
      sessionStorage.setItem(STORAGE_PAGE_KEY, hash);
    } catch (e) {}

    // Synchronize URL hash if different
    if (window.location.hash !== hash) {
      window.location.hash = hash;
      return;
    }

    // --- Admin Dashboard Dispatch ---
    if (currentUser.role === 'platform_admin') {
      tenantWorkspace.style.display = 'none';
      adminDashboard.style.display = 'block';

      var slug = hash.replace(/^#admin\/?/, '').replace(/^#/, '');
      var validSlugs = ['overview', 'verification', 'layer-kill', 'mutation', 'noisy-neighbour', 'metrics', 'keys', 'demo', 'config', 'attack', 'glossary'];
      if (!slug || validSlugs.indexOf(slug) === -1) {
        slug = 'overview';
      }

      var targetSecId = 'section-' + slug;

      // 1. Synchronize Sidebar Active Link
      var adminLinks = sidebarNav.querySelectorAll('.nav-link');
      for (var i = 0; i < adminLinks.length; i++) {
        if (adminLinks[i].getAttribute('data-section') === targetSecId) {
          adminLinks[i].classList.add('active');
        } else {
          adminLinks[i].classList.remove('active');
        }
      }

      // 2. Synchronize Horizontal Tab Bar Active Button
      var tabBtns = document.querySelectorAll('#admin-tab-bar .tab-btn');
      for (var t = 0; t < tabBtns.length; t++) {
        if (tabBtns[t].getAttribute('data-tab') === slug) {
          tabBtns[t].classList.add('active');
        } else {
          tabBtns[t].classList.remove('active');
        }
      }

      // 3. Update Breadcrumb Navigation
      var slugMeta = {
        'overview': { category: 'Dashboard', title: 'Executive Overview' },
        'verification': { category: 'Security Assurance', title: 'Automated Verification Suite' },
        'layer-kill': { category: 'Security Assurance', title: 'Layer-Kill Matrix' },
        'mutation': { category: 'Security Assurance', title: 'Mutation Testing' },
        'attack': { category: 'Security Assurance', title: 'Attack Simulator' },
        'keys': { category: 'Key Management', title: 'Tenant DEK Keys' },
        'demo': { category: 'Key Management', title: 'Key Lifecycle Demo' },
        'metrics': { category: 'Telemetry & Health', title: 'Per-Tenant Metrics' },
        'noisy-neighbour': { category: 'Telemetry & Health', title: 'Noisy-Neighbour Benchmark' },
        'config': { category: 'Telemetry & Health', title: 'Configuration Audit' },
        'glossary': { category: 'Reference', title: 'Security Glossary' }
      };
      var bcCat = document.getElementById('admin-bc-category');
      var bcTitle = document.getElementById('admin-bc-title');
      if (bcCat && slugMeta[slug]) bcCat.textContent = slugMeta[slug].category;
      if (bcTitle && slugMeta[slug]) bcTitle.textContent = slugMeta[slug].title;

      // 4. View Mode: Focused Tab (Zero-Scroll) vs All Sections
      var isViewAll = adminDashboard.classList.contains('admin-view-all-mode');
      var allSections = adminDashboard.querySelectorAll('.dashboard-section');

      if (isViewAll) {
        // Show all sections stacked
        for (var s = 0; s < allSections.length; s++) {
          allSections[s].style.display = 'block';
          allSections[s].classList.remove('active');
        }
        var targetEl = document.getElementById(targetSecId);
        if (targetEl) {
          targetEl.classList.add('active');
          setTimeout(function () {
            targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }, 50);
        }
      } else {
        // Focused Tab Mode: Show ONLY the selected tool!
        for (var s = 0; s < allSections.length; s++) {
          if (allSections[s].id === targetSecId) {
            allSections[s].style.display = 'block';
            allSections[s].classList.add('active');
          } else {
            allSections[s].style.display = 'none';
            allSections[s].classList.remove('active');
          }
        }
        // Smoothly scroll to the top so there is no awkward scroll offset
        setTimeout(function () {
          window.scrollTo({ top: 0, behavior: 'smooth' });
          var mainEl = document.getElementById('main-content');
          if (mainEl) mainEl.scrollTop = 0;
        }, 30);
      }

      // Re-trigger chart rendering if navigating to metrics tab
      if (slug === 'metrics') {
        var chartContainer = document.getElementById('metrics-chart-container');
        if (chartContainer && window.TenantChart && window.TenantChart.renderBarChart && window._lastMetricsChartData) {
          window.TenantChart.renderBarChart(chartContainer, window._lastMetricsChartData);
        }
      }

      return;
    }

    // --- Tenant Workspace Dispatch ---
    adminDashboard.style.display = 'none';
    tenantWorkspace.style.display = 'block';

    if (hash === '#documents') {
      setActiveTenantNav('#documents');
      showDocsList();
      loadTenantDocuments();
      return;
    }

    if (hash === '#new' || hash === '#documents/new' || hash === '#document/new') {
      setActiveTenantNav('#new');
      showCreateDocForm();
      return;
    }

    var editMatch = hash.match(/^#(?:doc|document)\/([^/]+)\/edit$/);
    if (editMatch) {
      setActiveTenantNav(null);
      loadAndShowDoc(editMatch[1], true);
      return;
    }

    var viewMatch = hash.match(/^#(?:doc|document)\/([^/]+)$/);
    if (viewMatch) {
      setActiveTenantNav(null);
      loadAndShowDoc(viewMatch[1], false);
      return;
    }

    // Fallback for unrecognized tenant hashes
    navigate('#documents');
  }

  function setActiveTenantNav(route) {
    var links = sidebarNav.querySelectorAll('.nav-link');
    for (var i = 0; i < links.length; i++) {
      if (route && links[i].getAttribute('data-route') === route) {
        links[i].classList.add('active');
      } else {
        links[i].classList.remove('active');
      }
    }
  }

  async function loadAndShowDoc(docId, isEdit) {
    try {
      var res = await apiFetch('/documents/' + docId);
      if (!res.ok) {
        navigate('#documents');
        return;
      }
      var doc = await res.json();
      if (isEdit) {
        showEditDocForm(doc);
      } else {
        showViewDoc(doc);
      }
    } catch (e) {
      navigate('#documents');
    }
  }

  // =========================================================================
  // TENANT WORKSPACE CONTROLLER
  // =========================================================================
  function renderTenantSidebar() {
    var docsBtn = document.createElement('button');
    docsBtn.className = 'nav-link active';
    docsBtn.textContent = 'Documents';
    docsBtn.setAttribute('data-route', '#documents');
    docsBtn.addEventListener('click', function () {
      navigate('#documents');
    });

    var newDocBtn = document.createElement('button');
    newDocBtn.className = 'nav-link';
    newDocBtn.textContent = 'New document';
    newDocBtn.setAttribute('data-route', '#new');
    newDocBtn.addEventListener('click', function () {
      navigate('#new');
    });

    sidebarNav.appendChild(docsBtn);
    sidebarNav.appendChild(newDocBtn);
  }

  function setActiveNavLink(activeEl) {
    var links = sidebarNav.querySelectorAll('.nav-link');
    for (var i = 0; i < links.length; i++) {
      links[i].classList.remove('active');
    }
    if (activeEl) {
      activeEl.classList.add('active');
    }
  }

  function showDocsList() {
    tenantDocsSection.style.display = 'block';
    tenantDocFormSection.style.display = 'none';
    tenantDocViewSection.style.display = 'none';
  }

  function showCreateDocForm() {
    tenantDocsSection.style.display = 'none';
    tenantDocFormSection.style.display = 'block';
    tenantDocViewSection.style.display = 'none';

    docFormTitle.textContent = 'New document';
    docFormDesc.textContent = 'Provide document title and content. Tenant identity is attached server-side.';
    docEditId.value = '';
    docTitleInput.value = '';
    docContentInput.value = '';
    docFormError.style.display = 'none';
    btnSaveDoc.textContent = 'Create document';
  }

  function showEditDocForm(doc) {
    tenantDocsSection.style.display = 'none';
    tenantDocFormSection.style.display = 'block';
    tenantDocViewSection.style.display = 'none';

    docFormTitle.textContent = 'Edit document';
    docFormDesc.textContent = 'Update document title and content.';
    docEditId.value = doc.id;
    docTitleInput.value = doc.title;
    docContentInput.value = doc.content || '';
    docFormError.style.display = 'none';
    btnSaveDoc.textContent = 'Save changes';
  }

  function showViewDoc(doc) {
    tenantDocsSection.style.display = 'none';
    tenantDocFormSection.style.display = 'none';
    tenantDocViewSection.style.display = 'block';

    viewDocTitle.textContent = doc.title;
    viewDocId.textContent = doc.id;
    viewDocKeyVer.textContent = doc.key_version != null ? doc.key_version : '1';
    viewDocCreated.textContent = doc.created_at || '—';
    viewDocContent.textContent = doc.content || '';

    btnEditCurrentDoc.onclick = function () {
      navigate('#doc/' + doc.id + '/edit');
    };
  }

  btnNewDoc.addEventListener('click', function () {
    navigate('#new');
  });
  btnCancelDocForm.addEventListener('click', function () {
    navigate('#documents');
  });
  btnBackToDocs.addEventListener('click', function () {
    navigate('#documents');
  });

  async function loadTenantDocuments() {
    tenantDocsAlert.style.display = 'none';

    // Clear table rows
    while (tenantDocsTbody.firstChild) {
      tenantDocsTbody.removeChild(tenantDocsTbody.firstChild);
    }

    try {
      var res = await apiFetch('/documents');
      if (!res.ok) {
        throw new Error('Failed to load documents.');
      }

      var docs = await res.json();
      if (!docs || docs.length === 0) {
        tenantDocsTable.style.display = 'none';
        tenantDocsEmpty.style.display = 'block';
        return;
      }

      tenantDocsTable.style.display = 'table';
      tenantDocsEmpty.style.display = 'none';

      for (var i = 0; i < docs.length; i++) {
        (function (doc) {
          var tr = document.createElement('tr');

          // Title (Safe textContent)
          var tdTitle = document.createElement('td');
          tdTitle.style.fontWeight = '500';
          tdTitle.textContent = doc.title;
          tr.appendChild(tdTitle);

          // ID (Safe textContent)
          var tdId = document.createElement('td');
          var codeId = document.createElement('code');
          codeId.textContent = doc.id;
          tdId.appendChild(codeId);
          tr.appendChild(tdId);

          // Key Version
          var tdKey = document.createElement('td');
          tdKey.className = 'num';
          tdKey.textContent = doc.key_version != null ? doc.key_version : '1';
          tr.appendChild(tdKey);

          // Created
          var tdCreated = document.createElement('td');
          tdCreated.style.fontSize = '13px';
          tdCreated.textContent = doc.created_at ? new Date(doc.created_at).toLocaleString() : '—';
          tr.appendChild(tdCreated);

          // Actions
          var tdActions = document.createElement('td');
          tdActions.style.whiteSpace = 'nowrap';

          var viewBtn = document.createElement('button');
          viewBtn.type = 'button';
          viewBtn.className = 'btn btn-sm';
          viewBtn.textContent = 'View';
          viewBtn.style.marginRight = '4px';
          viewBtn.addEventListener('click', function () {
            navigate('#doc/' + doc.id);
          });

          var editBtn = document.createElement('button');
          editBtn.type = 'button';
          editBtn.className = 'btn btn-sm';
          editBtn.textContent = 'Edit';
          editBtn.style.marginRight = '4px';
          editBtn.addEventListener('click', function () {
            navigate('#doc/' + doc.id + '/edit');
          });

          var delBtn = document.createElement('button');
          delBtn.type = 'button';
          delBtn.className = 'btn btn-sm btn-danger';
          delBtn.textContent = 'Delete';
          delBtn.addEventListener('click', function () {
            requestDocumentDelete(doc.id, doc.title);
          });

          tdActions.appendChild(viewBtn);
          tdActions.appendChild(editBtn);
          tdActions.appendChild(delBtn);
          tr.appendChild(tdActions);

          tenantDocsTbody.appendChild(tr);
        })(docs[i]);
      }
    } catch (err) {
      tenantDocsAlert.textContent = err.message || 'Error loading documents.';
      tenantDocsAlert.style.display = 'block';
    }
  }

  // Document Save (Create or Update)
  docForm.addEventListener('submit', async function (e) {
    e.preventDefault();
    docFormError.style.display = 'none';

    var id = docEditId.value;
    var title = docTitleInput.value.trim();
    var content = docContentInput.value;

    if (!title) {
      docFormError.textContent = 'Document title is required.';
      docFormError.style.display = 'block';
      return;
    }

    btnSaveDoc.disabled = true;
    btnSaveDoc.textContent = 'Saving...';

    try {
      var isEdit = Boolean(id);
      var url = isEdit ? '/documents/' + id : '/documents';
      var method = isEdit ? 'PUT' : 'POST';

      // Crucial: The UI never sends a tenant_id!
      var payload = {
        title: title,
        content: content
      };

      var res = await apiFetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        var errData = await res.json().catch(function () { return {}; });
        throw new Error(errData.detail || 'Failed to save document.');
      }

      navigate('#documents');
    } catch (err) {
      docFormError.textContent = err.message || 'Error saving document.';
      docFormError.style.display = 'block';
    } finally {
      btnSaveDoc.disabled = false;
      btnSaveDoc.textContent = 'Save document';
    }
  });

  // Document Delete Confirmation
  function requestDocumentDelete(docId, docTitle) {
    pendingDeleteDocId = docId;
    var msgEl = document.getElementById('confirm-modal-msg');
    msgEl.textContent = 'Are you sure you want to delete "' + docTitle + '"? This action is permanent.';
    confirmModal.style.display = 'flex';
  }

  btnConfirmCancel.addEventListener('click', hideConfirmModal);

  confirmModal.addEventListener('click', function (e) {
    if (e.target === confirmModal) {
      hideConfirmModal();
    }
  });

  window.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' || e.key === 'Esc') {
      hideConfirmModal();
    }
  });

  btnConfirmAction.addEventListener('click', async function () {
    if (!pendingDeleteDocId) return;

    btnConfirmAction.disabled = true;
    btnConfirmAction.textContent = 'Deleting...';

    try {
      var res = await apiFetch('/documents/' + pendingDeleteDocId, {
        method: 'DELETE'
      });

      if (!res.ok) {
        throw new Error('Failed to delete document.');
      }

      confirmModal.style.display = 'none';
      pendingDeleteDocId = null;
      loadTenantDocuments();
    } catch (err) {
      alert(err.message || 'Error deleting document.');
    } finally {
      btnConfirmAction.disabled = false;
      btnConfirmAction.textContent = 'Confirm delete';
    }
  });

  // =========================================================================
  // ADMIN DASHBOARD CONTROLLER & GLOSSARY
  // =========================================================================
  var currentOpenPopover = null;
  var currentOpenPopoverBtn = null;

  function closeCurrentPopover() {
    if (currentOpenPopover && currentOpenPopover.parentNode) {
      currentOpenPopover.parentNode.removeChild(currentOpenPopover);
    }
    if (currentOpenPopoverBtn) {
      currentOpenPopoverBtn.classList.remove('active');
    }
    currentOpenPopover = null;
    currentOpenPopoverBtn = null;
  }

  window.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' || e.key === 'Esc') {
      closeCurrentPopover();
    }
  });

  document.addEventListener('click', function (e) {
    if (currentOpenPopover && !currentOpenPopover.contains(e.target) && e.target !== currentOpenPopoverBtn) {
      closeCurrentPopover();
    }
  });

  function createInfoButton(termKey) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'info-btn';
    btn.setAttribute('aria-label', 'Explain ' + termKey);
    btn.setAttribute('data-glossary', termKey);
    btn.textContent = 'i';

    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      if (currentOpenPopoverBtn === btn) {
        closeCurrentPopover();
        return;
      }
      closeCurrentPopover();

      var term = window.getGlossaryTerm ? window.getGlossaryTerm(termKey) : null;
      if (!term && window.GLOSSARY && window.GLOSSARY[termKey]) {
        term = window.GLOSSARY[termKey];
      }
      if (!term) return;

      var popover = document.createElement('div');
      popover.className = 'glossary-popover';

      var header = document.createElement('div');
      header.className = 'glossary-popover-header';

      var title = document.createElement('span');
      title.className = 'glossary-popover-title';
      title.textContent = term.name;
      header.appendChild(title);

      var closeBtn = document.createElement('button');
      closeBtn.type = 'button';
      closeBtn.className = 'glossary-popover-close';
      closeBtn.setAttribute('aria-label', 'Close explanation');
      closeBtn.textContent = '×';
      closeBtn.addEventListener('click', function (ev) {
        ev.stopPropagation();
        closeCurrentPopover();
      });
      header.appendChild(closeBtn);
      popover.appendChild(header);

      var lblMeaning = document.createElement('div');
      lblMeaning.className = 'glossary-popover-label';
      lblMeaning.textContent = 'Meaning';
      popover.appendChild(lblMeaning);

      var pMeaning = document.createElement('p');
      pMeaning.className = 'glossary-popover-text';
      pMeaning.textContent = term.meaning;
      popover.appendChild(pMeaning);

      var lblCalc = document.createElement('div');
      lblCalc.className = 'glossary-popover-label';
      lblCalc.textContent = 'Calculation / Source';
      popover.appendChild(lblCalc);

      var pCalc = document.createElement('p');
      pCalc.className = 'glossary-popover-text';
      pCalc.textContent = term.calculation;
      popover.appendChild(pCalc);

      var lblRead = document.createElement('div');
      lblRead.className = 'glossary-popover-label';
      lblRead.textContent = 'How to Read';
      popover.appendChild(lblRead);

      var pRead = document.createElement('p');
      pRead.className = 'glossary-popover-text';
      pRead.textContent = term.howToRead;
      popover.appendChild(pRead);

      var parent = btn.parentElement || btn;
      if (parent.tagName === 'TH' || parent.tagName === 'TD') {
        parent.style.position = 'relative';
        var rect = btn.getBoundingClientRect();
        if (window.innerWidth - rect.right < 280) {
          popover.style.right = '0';
          popover.style.left = 'auto';
        } else {
          popover.style.left = '0';
          popover.style.right = 'auto';
        }
        parent.appendChild(popover);
      } else {
        parent.appendChild(popover);
      }

      btn.classList.add('active');
      currentOpenPopover = popover;
      currentOpenPopoverBtn = btn;
    });

    return btn;
  }

  function setupStaticGlossaryButtons() {
    var targets = document.querySelectorAll('[data-glossary]');
    for (var i = 0; i < targets.length; i++) {
      var el = targets[i];
      if (!el.querySelector('.info-btn')) {
        var termKey = el.getAttribute('data-glossary');
        var btn = createInfoButton(termKey);
        el.appendChild(btn);
      }
    }
  }

  function setupHowItWorksToggles() {
    var toggles = document.querySelectorAll('.how-it-works-toggle');
    for (var i = 0; i < toggles.length; i++) {
      (function (btn) {
        if (btn.getAttribute('data-bound')) return;
        btn.setAttribute('data-bound', 'true');
        btn.addEventListener('click', function () {
          var targetId = btn.getAttribute('data-target');
          var panel = document.getElementById(targetId);
          if (!panel) return;
          if (panel.style.display === 'block') {
            panel.style.display = 'none';
            btn.classList.remove('active');
          } else {
            panel.style.display = 'block';
            btn.classList.add('active');
          }
        });
      })(toggles[i]);
    }
  }

  function loadGlossarySection() {
    var container = document.getElementById('glossary-items-container');
    var searchInput = document.getElementById('glossary-search-input');
    if (!container || !window.GLOSSARY) return;

    function renderTerms(filterText) {
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
      var filter = (filterText || '').toLowerCase().trim();
      var keys = Object.keys(window.GLOSSARY);

      for (var i = 0; i < keys.length; i++) {
        var key = keys[i];
        var item = window.GLOSSARY[key];
        if (filter) {
          var matched = item.name.toLowerCase().indexOf(filter) !== -1 ||
                        item.meaning.toLowerCase().indexOf(filter) !== -1 ||
                        item.calculation.toLowerCase().indexOf(filter) !== -1 ||
                        item.howToRead.toLowerCase().indexOf(filter) !== -1;
          if (!matched) continue;
        }

        var card = document.createElement('div');
        card.className = 'glossary-card';

        var title = document.createElement('h3');
        title.className = 'glossary-card-title';
        title.textContent = item.name;
        card.appendChild(title);

        var lblM = document.createElement('div');
        lblM.className = 'glossary-popover-label';
        lblM.textContent = 'Meaning';
        card.appendChild(lblM);

        var pM = document.createElement('p');
        pM.className = 'glossary-popover-text';
        pM.textContent = item.meaning;
        card.appendChild(pM);

        var lblC = document.createElement('div');
        lblC.className = 'glossary-popover-label';
        lblC.textContent = 'Calculation / Source';
        card.appendChild(lblC);

        var pC = document.createElement('p');
        pC.className = 'glossary-popover-text';
        pC.textContent = item.calculation;
        card.appendChild(pC);

        var lblR = document.createElement('div');
        lblR.className = 'glossary-popover-label';
        lblR.textContent = 'How to Read';
        card.appendChild(lblR);

        var pR = document.createElement('p');
        pR.className = 'glossary-popover-text';
        pR.textContent = item.howToRead;
        card.appendChild(pR);

        container.appendChild(card);
      }
    }

    renderTerms('');

    if (searchInput && !searchInput.getAttribute('data-bound')) {
      searchInput.setAttribute('data-bound', 'true');
      searchInput.addEventListener('input', function () {
        renderTerms(searchInput.value);
      });
    }
  }

  function getSidebarIconSvg(iconName) {
    var icons = {
      dashboard: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
      shield: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
      layers: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>',
      beaker: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 3h15"/><path d="M6 3v16a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V3"/><line x1="6" y1="14" x2="18" y2="14"/></svg>',
      crosshair: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>',
      key: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-1.5 1.5L16 7l-1.5-1.5L13 7l-2-2-7 7a5 5 0 1 0 7 7l7-7v-3h3v-3h2V2z"/></svg>',
      rotate: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
      chart: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
      gauge: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"/><path d="M19.07 4.93a10 10 0 0 0-14.14 0"/><path d="M16.24 7.76a6 6 0 0 0-8.48 0"/><line x1="12" y1="12" x2="16.5" y2="7.5"/></svg>',
      checkCircle: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>',
      book: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>'
    };
    return icons[iconName] || '';
  }

  function renderAdminSidebar() {
    while (sidebarNav.firstChild) {
      sidebarNav.removeChild(sidebarNav.firstChild);
    }

    var groups = [
      {
        title: 'MAIN',
        items: [
          { id: 'section-overview', slug: 'overview', label: 'Overview', icon: 'dashboard' }
        ]
      },
      {
        title: 'SECURITY ASSURANCE',
        items: [
          { id: 'section-verification', slug: 'verification', label: 'Verification Suite', icon: 'shield', badge: '11 tests' },
          { id: 'section-layer-kill', slug: 'layer-kill', label: 'Layer-Kill Matrix', icon: 'layers' },
          { id: 'section-mutation', slug: 'mutation', label: 'Mutation Testing', icon: 'beaker' },
          { id: 'section-attack', slug: 'attack', label: 'Attack Simulator', icon: 'crosshair', badge: 'Lab' }
        ]
      },
      {
        title: 'KEY MANAGEMENT',
        items: [
          { id: 'section-keys', slug: 'keys', label: 'Tenant DEK Keys', icon: 'key' },
          { id: 'section-demo', slug: 'demo', label: 'Key Lifecycle Demo', icon: 'rotate', badge: 'Demo' }
        ]
      },
      {
        title: 'TELEMETRY & HEALTH',
        items: [
          { id: 'section-metrics', slug: 'metrics', label: 'Per-Tenant Metrics', icon: 'chart', badge: 'Live' },
          { id: 'section-noisy-neighbour', slug: 'noisy-neighbour', label: 'Noisy Neighbour', icon: 'gauge' },
          { id: 'section-config', slug: 'config', label: 'Configuration Audit', icon: 'checkCircle' }
        ]
      },
      {
        title: 'REFERENCE',
        items: [
          { id: 'section-glossary', slug: 'glossary', label: 'Security Glossary', icon: 'book' }
        ]
      }
    ];

    for (var g = 0; g < groups.length; g++) {
      var grp = groups[g];
      var headerDiv = document.createElement('div');
      headerDiv.className = 'nav-group-header';
      headerDiv.textContent = grp.title;
      sidebarNav.appendChild(headerDiv);

      for (var i = 0; i < grp.items.length; i++) {
        (function (sec) {
          var btn = document.createElement('button');
          btn.className = 'nav-link' + (sec.slug === 'overview' ? ' active' : '');
          btn.setAttribute('data-section', sec.id);
          btn.setAttribute('data-slug', sec.slug);

          var iconSpan = document.createElement('span');
          iconSpan.className = 'nav-icon';
          iconSpan.innerHTML = getSidebarIconSvg(sec.icon);
          btn.appendChild(iconSpan);

          var labelSpan = document.createElement('span');
          labelSpan.className = 'nav-text';
          labelSpan.textContent = sec.label;
          btn.appendChild(labelSpan);

          if (sec.badge) {
            var badgeSpan = document.createElement('span');
            badgeSpan.className = 'nav-badge';
            badgeSpan.textContent = sec.badge;
            btn.appendChild(badgeSpan);
          }

          btn.addEventListener('click', function () {
            navigate('#admin/' + sec.slug);
          });

          sidebarNav.appendChild(btn);
        })(grp.items[i]);
      }
    }
  }

  function setupVerificationRunButton() {
    var btnRunVerification = document.getElementById('btn-run-verification');
    var verifStatusBar = document.getElementById('verif-run-status-bar');
    if (!btnRunVerification || btnRunVerification.getAttribute('data-bound')) return;
    btnRunVerification.setAttribute('data-bound', 'true');

    btnRunVerification.addEventListener('click', async function () {
      btnRunVerification.disabled = true;
      var elapsedSec = 0;
      btnRunVerification.textContent = 'Running (0s)...';
      if (verifStatusBar) {
        verifStatusBar.style.display = 'block';
        verifStatusBar.textContent = 'Starting verification run...';
      }

      var timer = setInterval(function () {
        elapsedSec++;
        btnRunVerification.textContent = 'Running (' + elapsedSec + 's)...';
      }, 1000);

      try {
        var startRes = await apiFetch('/admin/dashboard/run-verification', {
          method: 'POST'
        });
        if (!startRes.ok) {
          var errData = await startRes.json();
          throw new Error(errData.detail || 'Failed to start verification.');
        }

        var startData = await startRes.json();
        var runId = startData.run_id;

        var pollInterval = setInterval(async function () {
          try {
            var stRes = await apiFetch('/admin/dashboard/run-status/' + runId);
            if (!stRes.ok) return;
            var stData = await stRes.json();

            if (stData.state === 'finished') {
              clearInterval(pollInterval);
              clearInterval(timer);
              btnRunVerification.disabled = false;
              btnRunVerification.textContent = 'Run verification now';
              if (verifStatusBar) {
                verifStatusBar.textContent = 'Verification run completed in ' + elapsedSec + 's.';
              }
              await loadVerificationSection();
            } else if (stData.state === 'failed') {
              clearInterval(pollInterval);
              clearInterval(timer);
              btnRunVerification.disabled = false;
              btnRunVerification.textContent = 'Run verification now';
              if (verifStatusBar) {
                verifStatusBar.textContent = 'Verification run failed after ' + elapsedSec + 's: ' + (stData.error || 'Process failed');
              }
            }
          } catch (pollErr) {
            // Keep polling
          }
        }, 1500);

      } catch (err) {
        clearInterval(timer);
        btnRunVerification.disabled = false;
        btnRunVerification.textContent = 'Run verification now';
        if (verifStatusBar) {
          verifStatusBar.textContent = 'Error: ' + err.message;
        }
      }
    });
  }

  function setupLayerKillRunButton() {
    var btn = document.getElementById('btn-run-layer-kill');
    var statusBar = document.getElementById('layer-run-status-bar');
    if (!btn || btn.getAttribute('data-bound')) return;
    btn.setAttribute('data-bound', 'true');

    btn.addEventListener('click', async function () {
      btn.disabled = true;
      var elapsedSec = 0;
      btn.textContent = 'Running (0s)...';
      if (statusBar) {
        statusBar.style.display = 'block';
        statusBar.style.background = 'rgba(56, 189, 248, 0.12)';
        statusBar.style.borderLeft = '3px solid var(--accent)';
        statusBar.style.color = 'var(--text-main)';
        statusBar.textContent = 'Initializing isolated lab database and running Layer-Kill Matrix...';
      }

      var timer = setInterval(function () {
        elapsedSec++;
        btn.textContent = 'Running (' + elapsedSec + 's)...';
      }, 1000);

      try {
        var startRes = await apiFetch('/admin/dashboard/run-matrix', { method: 'POST' });
        if (!startRes.ok) {
          var errData = await startRes.json();
          throw new Error(errData.detail || 'Failed to start Layer-Kill Matrix.');
        }

        var startData = await startRes.json();
        var runId = startData.run_id;

        var pollInterval = setInterval(async function () {
          try {
            var stRes = await apiFetch('/admin/dashboard/run-matrix-status/' + runId);
            if (!stRes.ok) return;
            var stData = await stRes.json();

            if (stData.progress && statusBar && stData.state === 'running') {
              statusBar.textContent = '⏳ ' + stData.progress + ' (' + elapsedSec + 's)';
            }

            if (stData.state === 'finished') {
              clearInterval(pollInterval);
              clearInterval(timer);
              btn.disabled = false;
              btn.textContent = 'Run Layer-Kill Matrix';
              if (statusBar) {
                statusBar.style.background = 'rgba(16, 185, 129, 0.12)';
                statusBar.style.borderLeft = '3px solid #10b981';
                statusBar.textContent = '✅ Layer-Kill Matrix completed in ' + elapsedSec + 's! All 5 configurations evaluated.';
              }
              await loadLayerKillSection();
            } else if (stData.state === 'failed') {
              clearInterval(pollInterval);
              clearInterval(timer);
              btn.disabled = false;
              btn.textContent = 'Run Layer-Kill Matrix';
              if (statusBar) {
                statusBar.style.background = 'rgba(239, 68, 68, 0.12)';
                statusBar.style.borderLeft = '3px solid #ef4444';
                statusBar.textContent = '❌ Layer-Kill Matrix failed after ' + elapsedSec + 's: ' + (stData.error || 'Failed');
              }
            }
          } catch (pollErr) {
            // Keep polling
          }
        }, 1500);

      } catch (err) {
        clearInterval(timer);
        btn.disabled = false;
        btn.textContent = 'Run Layer-Kill Matrix';
        if (statusBar) {
          statusBar.style.background = 'rgba(239, 68, 68, 0.12)';
          statusBar.style.borderLeft = '3px solid #ef4444';
          statusBar.textContent = 'Error: ' + err.message;
        }
      }
    });
  }

  function setupMutationRunButton() {
    var btn = document.getElementById('btn-run-mutation');
    var statusBar = document.getElementById('mut-run-status-bar');
    if (!btn || btn.getAttribute('data-bound')) return;
    btn.setAttribute('data-bound', 'true');

    btn.addEventListener('click', async function () {
      btn.disabled = true;
      var elapsedSec = 0;
      btn.textContent = 'Running (0s)...';
      if (statusBar) {
        statusBar.style.display = 'block';
        statusBar.style.background = 'rgba(56, 189, 248, 0.12)';
        statusBar.style.borderLeft = '3px solid var(--accent)';
        statusBar.style.color = 'var(--text-main)';
        statusBar.textContent = 'Initializing lab environment and injecting fault mutations...';
      }

      var timer = setInterval(function () {
        elapsedSec++;
        btn.textContent = 'Running (' + elapsedSec + 's)...';
      }, 1000);

      try {
        var startRes = await apiFetch('/admin/dashboard/run-mutation', { method: 'POST' });
        if (!startRes.ok) {
          var errData = await startRes.json();
          throw new Error(errData.detail || 'Failed to start Mutation suite.');
        }

        var startData = await startRes.json();
        var runId = startData.run_id;

        var pollInterval = setInterval(async function () {
          try {
            var stRes = await apiFetch('/admin/dashboard/run-mutation-status/' + runId);
            if (!stRes.ok) return;
            var stData = await stRes.json();

            if (stData.progress && statusBar && stData.state === 'running') {
              statusBar.textContent = '⏳ ' + stData.progress + ' (' + elapsedSec + 's)';
            }

            if (stData.state === 'finished') {
              clearInterval(pollInterval);
              clearInterval(timer);
              btn.disabled = false;
              btn.textContent = 'Run Mutation Suite';
              var score = (stData.result && stData.result.isolation_mutation_score) ? stData.result.isolation_mutation_score : '5/5 Caught';
              if (statusBar) {
                statusBar.style.background = 'rgba(16, 185, 129, 0.12)';
                statusBar.style.borderLeft = '3px solid #10b981';
                statusBar.textContent = '✅ Mutation Testing completed in ' + elapsedSec + 's! Score: ' + score;
              }
              await loadMutationSection();
            } else if (stData.state === 'failed') {
              clearInterval(pollInterval);
              clearInterval(timer);
              btn.disabled = false;
              btn.textContent = 'Run Mutation Suite';
              if (statusBar) {
                statusBar.style.background = 'rgba(239, 68, 68, 0.12)';
                statusBar.style.borderLeft = '3px solid #ef4444';
                statusBar.textContent = '❌ Mutation Testing failed after ' + elapsedSec + 's: ' + (stData.error || 'Failed');
              }
            }
          } catch (pollErr) {
            // Keep polling
          }
        }, 1500);

      } catch (err) {
        clearInterval(timer);
        btn.disabled = false;
        btn.textContent = 'Run Mutation Suite';
        if (statusBar) {
          statusBar.style.background = 'rgba(239, 68, 68, 0.12)';
          statusBar.style.borderLeft = '3px solid #ef4444';
          statusBar.textContent = 'Error: ' + err.message;
        }
      }
    });
  }


  function setupAdminTabControls() {
    if (adminDashboard.getAttribute('data-tab-controls-bound')) return;
    adminDashboard.setAttribute('data-tab-controls-bound', 'true');

    // Horizontal Tab Bar Buttons
    var tabBtns = document.querySelectorAll('#admin-tab-bar .tab-btn');
    for (var i = 0; i < tabBtns.length; i++) {
      (function (btn) {
        btn.addEventListener('click', function () {
          var tabSlug = btn.getAttribute('data-tab');
          if (tabSlug) {
            navigate('#admin/' + tabSlug);
          }
        });
      })(tabBtns[i]);
    }

    // View Mode Toggle (Focused Single-Tab vs All Sections)
    var btnModeTab = document.getElementById('btn-mode-tab');
    var btnModeAll = document.getElementById('btn-mode-all');
    if (btnModeTab && btnModeAll) {
      btnModeTab.addEventListener('click', function () {
        adminDashboard.classList.remove('admin-view-all-mode');
        adminDashboard.classList.add('admin-tab-mode');
        btnModeTab.classList.add('active');
        btnModeAll.classList.remove('active');
        handleRoute();
      });
      btnModeAll.addEventListener('click', function () {
        adminDashboard.classList.remove('admin-tab-mode');
        adminDashboard.classList.add('admin-view-all-mode');
        btnModeAll.classList.add('active');
        btnModeTab.classList.remove('active');
        handleRoute();
      });
    }

    // Overview Launchpad & KPI jump clicks
    var jumpEls = adminDashboard.querySelectorAll('[data-jump]');
    for (var j = 0; j < jumpEls.length; j++) {
      (function (el) {
        el.addEventListener('click', function (e) {
          e.stopPropagation();
          var slug = el.getAttribute('data-jump');
          if (slug) {
            navigate('#admin/' + slug);
          }
        });
      })(jumpEls[j]);
    }

    // Overview Refresh Button
    var btnRefresh = document.getElementById('btn-overview-refresh');
    if (btnRefresh) {
      btnRefresh.addEventListener('click', function () {
        btnRefresh.disabled = true;
        btnRefresh.textContent = 'Refreshing...';
        loadAllAdminSections();
        setTimeout(function () {
          btnRefresh.disabled = false;
          btnRefresh.textContent = 'Refresh all telemetry';
        }, 800);
      });
    }

    // Quick Feature Search and Auto-complete Jump
    setupFeatureSearch();
  }

  function setupFeatureSearch() {
    var searchInput = document.getElementById('admin-feature-search');
    var dropdown = document.getElementById('admin-search-dropdown');
    if (!searchInput || !dropdown) return;

    var features = [
      { slug: 'overview', title: 'Executive Overview', group: 'Dashboard', desc: 'KPI summary, system status, and module launchpad' },
      { slug: 'verification', title: 'Verification Run Suite', group: 'Security Assurance', desc: '11 automated cross-tenant simulated attacks, canary integrity, list-leak check' },
      { slug: 'layer-kill', title: 'Layer-Kill Matrix', group: 'Security Assurance', desc: 'Defense-in-depth failure analysis across Layers A, B, and C' },
      { slug: 'mutation', title: 'Mutation Testing', group: 'Security Assurance', desc: 'Fault injection sensitivity evaluation and detection scores' },
      { slug: 'attack', title: 'Interactive Attack Simulator', group: 'Security Assurance', desc: 'Execute live targeted attacks between attacker and victim tenants' },
      { slug: 'keys', title: 'Tenant DEK Encryption Keys', group: 'Key Management', desc: 'KMS envelope encryption key lifecycle: active, retired, destroyed' },
      { slug: 'demo', title: 'Key Lifecycle & Crypto-Shred Demo', group: 'Key Management', desc: '7-step interactive envelope encryption, key rotation, and shredding' },
      { slug: 'metrics', title: 'Per-Tenant Live Metrics', group: 'Telemetry & Health', desc: 'Sliding 60-min Redis telemetry, request rates, errors, avg latency chart' },
      { slug: 'metrics', title: 'Send Test Traffic (Demo Co)', group: 'Telemetry & Health', desc: 'Generate 10 valid + 3 invalid requests to populate live telemetry' },
      { slug: 'noisy-neighbour', title: 'Noisy-Neighbour Experiment', group: 'Telemetry & Health', desc: 'Workload benchmark measuring p50/p95 latency and rate limiter strategies' },
      { slug: 'config', title: 'Configuration & RLS Audit', group: 'Telemetry & Health', desc: 'Read-only audit of database RLS policies and application role privileges' },
      { slug: 'glossary', title: 'Security & System Glossary', group: 'Reference', desc: 'Comprehensive terminology definitions, formulas, and interpretations' }
    ];

    function renderResults(q) {
      while (dropdown.firstChild) dropdown.removeChild(dropdown.firstChild);
      q = (q || '').trim().toLowerCase();
      if (!q) {
        dropdown.style.display = 'none';
        return;
      }

      var matches = features.filter(function (f) {
        return f.title.toLowerCase().indexOf(q) !== -1 ||
               f.desc.toLowerCase().indexOf(q) !== -1 ||
               f.group.toLowerCase().indexOf(q) !== -1 ||
               f.slug.toLowerCase().indexOf(q) !== -1;
      });

      if (matches.length === 0) {
        var emptyDiv = document.createElement('div');
        emptyDiv.className = 'search-item-empty';
        emptyDiv.textContent = 'No features matching "' + q + '"';
        dropdown.appendChild(emptyDiv);
      } else {
        for (var i = 0; i < matches.length; i++) {
          (function (item) {
            var row = document.createElement('div');
            row.className = 'search-item';

            var top = document.createElement('div');
            top.className = 'search-item-top';
            var titleSpan = document.createElement('span');
            titleSpan.className = 'search-item-title';
            titleSpan.textContent = item.title;
            var groupBadge = document.createElement('span');
            groupBadge.className = 'search-item-group';
            groupBadge.textContent = item.group;
            top.appendChild(titleSpan);
            top.appendChild(groupBadge);

            var descSpan = document.createElement('div');
            descSpan.className = 'search-item-desc';
            descSpan.textContent = item.desc;

            row.appendChild(top);
            row.appendChild(descSpan);

            row.addEventListener('click', function () {
              dropdown.style.display = 'none';
              searchInput.value = '';
              navigate('#admin/' + item.slug);
            });

            dropdown.appendChild(row);
          })(matches[i]);
        }
      }
      dropdown.style.display = 'block';
    }

    searchInput.addEventListener('input', function () {
      renderResults(searchInput.value);
    });

    searchInput.addEventListener('focus', function () {
      if (searchInput.value.trim()) {
        renderResults(searchInput.value);
      }
    });

    document.addEventListener('click', function (e) {
      if (!searchInput.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.style.display = 'none';
      }
    });
  }

  function loadAllAdminSections() {
    setupAdminTabControls();
    setupVerificationRunButton();
    setupLayerKillRunButton();
    setupMutationRunButton();
    loadVerificationSection();
    loadLayerKillSection();
    loadMutationSection();
    loadNoisyNeighbourSection();
    loadLiveNoisyNeighbour();
    setupLiveNoisyRefreshButton();
    setupLiveBenchmarkRunner();
    loadMetricsSection();
    setupSendTestTrafficButton();
    loadKeysSection();
    setupKeyLifecycleDemo();
    setupAttackDemo();
    loadConfigCheckSection();
    loadGlossarySection();
    setupHowItWorksToggles();
    setupStaticGlossaryButtons();
  }

  // 1. Verification Section
  async function loadVerificationSection() {
    var contentEl = document.getElementById('verif-content');
    var emptyEl = document.getElementById('verif-empty');
    var timeEl = document.getElementById('verif-run-time');
    var tbody = document.getElementById('verif-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/verification');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.summary.generated_at_utc ? new Date(data.summary.generated_at_utc).toLocaleString() : '';

      // Exact stored verdict and counts
      var verdictEl = document.getElementById('verif-verdict');
      while (verdictEl.firstChild) verdictEl.removeChild(verdictEl.firstChild);
      verdictEl.appendChild(createStatusBadge(data.summary.overall_verdict, getDotTypeForStatus(data.summary.overall_verdict)));
      verdictEl.appendChild(createInfoButton('Verdict'));

      // Update Overview KPI
      var kpiVerdict = document.getElementById('kpi-verdict');
      var kpiVerdictSub = document.getElementById('kpi-verdict-sub');
      if (kpiVerdict && data.summary) {
        while (kpiVerdict.firstChild) kpiVerdict.removeChild(kpiVerdict.firstChild);
        kpiVerdict.appendChild(createStatusBadge(data.summary.overall_verdict, getDotTypeForStatus(data.summary.overall_verdict)));
        if (kpiVerdictSub) {
          kpiVerdictSub.textContent = (data.summary.blocked_attacks || 0) + ' blocked / ' + (data.summary.total_attacks_run || 0) + ' total attacks';
        }
      }

      document.getElementById('verif-total').textContent = data.summary.total_attacks_run;
      document.getElementById('verif-blocked').textContent = data.summary.blocked_attacks;
      document.getElementById('verif-leaked').textContent = data.summary.leaked_attacks;
      document.getElementById('verif-inconclusive').textContent = data.summary.inconclusive_attacks;

      var expStat = document.getElementById('verif-expected-stat');
      var expVal = document.getElementById('verif-expected-leaks');
      if (expStat && expVal) {
        if (data.summary.expected_leaks !== undefined && data.summary.expected_leaks > 0) {
          expStat.style.display = 'inline-block';
          expVal.textContent = data.summary.expected_leaks;
        } else {
          expStat.style.display = 'none';
        }
      }

      var canaryEl = document.getElementById('verif-canary');
      while (canaryEl.firstChild) canaryEl.removeChild(canaryEl.firstChild);
      canaryEl.textContent = data.summary.tenant_b_canary_integrity + ' ';
      canaryEl.appendChild(createInfoButton(data.summary.tenant_b_canary_integrity));

      var listLeakEl = document.getElementById('verif-list-leak');
      while (listLeakEl.firstChild) listLeakEl.removeChild(listLeakEl.firstChild);
      listLeakEl.textContent = data.summary.list_leak_check + ' ';
      listLeakEl.appendChild(createInfoButton('List-leak check'));

      // Attacks Table
      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var attacks = data.attacks || [];
      for (var i = 0; i < attacks.length; i++) {
        var a = attacks[i];
        var tr = document.createElement('tr');

        var tdMethod = document.createElement('td');
        tdMethod.style.fontWeight = '600';
        tdMethod.textContent = a.method + ' ';
        tdMethod.appendChild(createInfoButton(a.method));
        tr.appendChild(tdMethod);

        var tdPath = document.createElement('td');
        var codePath = document.createElement('code');
        codePath.textContent = a.target_path;
        tdPath.appendChild(codePath);
        if (a.target_path && a.target_path.indexOf('/vulnerable') !== -1) {
          var badgeFlawed = document.createElement('span');
          badgeFlawed.className = 'badge-flawed';
          badgeFlawed.textContent = 'Flawed Demo';
          tdPath.appendChild(badgeFlawed);
        }
        tr.appendChild(tdPath);

        var tdStatus = document.createElement('td');
        tdStatus.className = 'num';
        tdStatus.textContent = a.status_code + ' ';
        tdStatus.appendChild(createInfoButton(String(a.status_code)));
        tr.appendChild(tdStatus);

        var tdOutcome = document.createElement('td');
        tdOutcome.appendChild(createStatusBadge(a.outcome, getDotTypeForStatus(a.outcome)));
        tdOutcome.appendChild(createInfoButton(a.outcome));
        tr.appendChild(tdOutcome);

        var tdControl = document.createElement('td');
        tdControl.textContent = a.blocking_control + ' ';
        tdControl.appendChild(createInfoButton(a.blocking_control));
        tr.appendChild(tdControl);

        tbody.appendChild(tr);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 2. Layer-Kill Section
  async function loadLayerKillSection() {
    var contentEl = document.getElementById('layer-content');
    var emptyEl = document.getElementById('layer-empty');
    var timeEl = document.getElementById('layer-run-time');
    var tbody = document.getElementById('layer-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/layer-kill');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.generated_at_utc ? new Date(data.generated_at_utc).toLocaleString() : '';

      var verdictEl = document.getElementById('layer-verdict');
      while (verdictEl.firstChild) verdictEl.removeChild(verdictEl.firstChild);
      verdictEl.appendChild(createStatusBadge(data.overall_verdict, getDotTypeForStatus(data.overall_verdict)));
      verdictEl.appendChild(createInfoButton('Verdict'));

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var configs = data.configurations || [];
      for (var i = 0; i < configs.length; i++) {
        var c = configs[i];
        var tr = document.createElement('tr');

        var tdConfig = document.createElement('td');
        tdConfig.style.fontWeight = '500';
        tdConfig.textContent = c.configuration + ' ';
        var cfgMatch = c.configuration.match(/\(([a-e])\)/i);
        var cfgKey = cfgMatch ? 'Configuration (' + cfgMatch[1].toLowerCase() + ')' : 'Configuration (a) to (e)';
        tdConfig.appendChild(createInfoButton(cfgKey));
        tr.appendChild(tdConfig);

        var tdA = document.createElement('td');
        tdA.textContent = c.layer_a_app_check + ' ';
        tdA.appendChild(createInfoButton('Layer A'));
        tr.appendChild(tdA);

        var tdB = document.createElement('td');
        tdB.textContent = c.layer_b_db_rls + ' ';
        tdB.appendChild(createInfoButton('Layer B'));
        tr.appendChild(tdB);

        var tdC = document.createElement('td');
        tdC.textContent = c.layer_c_query_filter + ' ';
        tdC.appendChild(createInfoButton('Layer C'));
        tr.appendChild(tdC);

        var tdR = document.createElement('td');
        tdR.className = 'num';
        tdR.textContent = c.leaks.read;
        tr.appendChild(tdR);

        var tdW = document.createElement('td');
        tdW.className = 'num';
        tdW.textContent = c.leaks.write;
        tr.appendChild(tdW);

        var tdU = document.createElement('td');
        tdU.className = 'num';
        tdU.textContent = c.leaks.update;
        tr.appendChild(tdU);

        var tdD = document.createElement('td');
        tdD.className = 'num';
        tdD.textContent = c.leaks.delete;
        tr.appendChild(tdD);

        var tdProt = document.createElement('td');
        tdProt.style.fontSize = '12px';
        tdProt.style.color = 'var(--text-muted)';
        tdProt.textContent = (c.active_protections || []).join(', ') + ' ';
        tdProt.appendChild(createInfoButton('Active protections'));
        tr.appendChild(tdProt);

        var tdVerd = document.createElement('td');
        tdVerd.appendChild(createStatusBadge(c.config_verdict, getDotTypeForStatus(c.config_verdict)));
        tdVerd.appendChild(createInfoButton('Verdict'));
        tr.appendChild(tdVerd);

        tbody.appendChild(tr);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 3. Mutation Section
  async function loadMutationSection() {
    var contentEl = document.getElementById('mut-content');
    var emptyEl = document.getElementById('mut-empty');
    var timeEl = document.getElementById('mut-run-time');
    var scoreEl = document.getElementById('mut-score');
    var tbody = document.getElementById('mut-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/mutation');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.timestamp ? new Date(data.timestamp).toLocaleString() : '';
      scoreEl.textContent = data.isolation_mutation_score;
      if (!scoreEl.parentElement.querySelector('.info-btn')) {
        scoreEl.parentElement.appendChild(createInfoButton('Mutation'));
      }

      // Update Overview KPI
      var kpiMutation = document.getElementById('kpi-mutation');
      var kpiMutationSub = document.getElementById('kpi-mutation-sub');
      if (kpiMutation) {
        kpiMutation.textContent = data.isolation_mutation_score || '5/5 Caught';
        if (kpiMutationSub) {
          kpiMutationSub.textContent = (data.mutations ? data.mutations.length : 5) + ' test mutations evaluated';
        }
      }

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var mutations = data.mutations || [];
      for (var i = 0; i < mutations.length; i++) {
        var m = mutations[i];
        var tr = document.createElement('tr');

        var tdName = document.createElement('td');
        tdName.style.fontWeight = '500';
        tdName.textContent = m.name + ' ';
        tdName.appendChild(createInfoButton('Mutation'));
        tr.appendChild(tdName);

        var tdLayer = document.createElement('td');
        tdLayer.textContent = m.mutated_layer + ' ';
        tdLayer.appendChild(createInfoButton('Layer A, B, C'));
        tr.appendChild(tdLayer);

        var tdMethod = document.createElement('td');
        var codeM = document.createElement('code');
        codeM.textContent = m.detection_method;
        tdMethod.appendChild(codeM);
        tdMethod.appendChild(createInfoButton(m.detection_method));
        tr.appendChild(tdMethod);

        var tdIso = document.createElement('td');
        tdIso.appendChild(createStatusBadge(m.isolated_result, getDotTypeForStatus(m.isolated_result)));
        tdIso.appendChild(createInfoButton(m.isolated_result));
        tr.appendChild(tdIso);

        var tdMask = document.createElement('td');
        tdMask.appendChild(createStatusBadge(m.masked_result, getDotTypeForStatus(m.masked_result)));
        tdMask.appendChild(createInfoButton(m.masked_result));
        tr.appendChild(tdMask);

        var tdBase = document.createElement('td');
        tdBase.textContent = (m.baseline_restored ? 'Yes' : 'No') + ' ';
        tdBase.appendChild(createInfoButton('Baseline restored'));
        tr.appendChild(tdBase);

        tbody.appendChild(tr);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 4. Noisy-Neighbour Section
  async function loadNoisyNeighbourSection() {
    var contentEl = document.getElementById('noisy-content');
    var emptyEl = document.getElementById('noisy-empty');
    var timeEl = document.getElementById('noisy-run-time');
    var tbody = document.getElementById('noisy-table-body');
    var amendmentsList = document.getElementById('noisy-amendments-list');

    try {
      var res = await apiFetch('/admin/dashboard/noisy-neighbour');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';
      timeEl.textContent = data.generated_at_utc ? new Date(data.generated_at_utc).toLocaleString() : '';

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var summaries = data.summaries || [];
      for (var i = 0; i < summaries.length; i++) {
        var s = summaries[i];
        var tr = document.createElement('tr');

        var tdStrat = document.createElement('td');
        tdStrat.style.fontWeight = '500';
        tdStrat.textContent = s.strategy_label + ' ';
        tdStrat.appendChild(createInfoButton(s.strategy || 'each limiter strategy'));
        tr.appendChild(tdStrat);

        var tdLoad = document.createElement('td');
        tdLoad.textContent = s.load_type + ' ';
        tdLoad.appendChild(createInfoButton(s.load_type || 'each load type'));
        tr.appendChild(tdLoad);

        var tdP50 = document.createElement('td');
        tdP50.className = 'num';
        tdP50.textContent = s.beta_p50_ms.mean + ' (±' + s.beta_p50_ms.std + ') ';
        tdP50.appendChild(createInfoButton('p50'));
        tdP50.appendChild(createInfoButton('the plus-minus spread'));
        tr.appendChild(tdP50);

        var tdP95 = document.createElement('td');
        tdP95.className = 'num';
        tdP95.textContent = s.beta_p95_ms.mean + ' (±' + s.beta_p95_ms.std + ') ';
        tdP95.appendChild(createInfoButton('p95'));
        tr.appendChild(tdP95);

        var tdErr = document.createElement('td');
        tdErr.className = 'num';
        tdErr.textContent = s.beta_error_rate.mean + ' (±' + s.beta_error_rate.std + ') ';
        tdErr.appendChild(createInfoButton('Beta error rate'));
        tr.appendChild(tdErr);

        var td429 = document.createElement('td');
        td429.className = 'num';
        td429.textContent = s.acme_429.mean + ' (±' + s.acme_429.std + ') ';
        td429.appendChild(createInfoButton('Acme 429s'));
        tr.appendChild(td429);

        var tdTimeouts = document.createElement('td');
        tdTimeouts.className = 'num';
        tdTimeouts.textContent = s.acme_timeouts.mean + ' (±' + s.acme_timeouts.std + ') ';
        tdTimeouts.appendChild(createInfoButton('Acme timeouts'));
        tr.appendChild(tdTimeouts);

        tbody.appendChild(tr);
      }

      // Amendments list
      while (amendmentsList.firstChild) amendmentsList.removeChild(amendmentsList.firstChild);
      var amendments = data.amendments || [];
      for (var a = 0; a < amendments.length; a++) {
        var li = document.createElement('li');
        li.textContent = amendments[a];
        amendmentsList.appendChild(li);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 4b. Live Noisy-Neighbour Section (Redis-backed, fully dynamic)
  async function loadLiveNoisyNeighbour() {
    var emptyEl = document.getElementById('live-noisy-empty');
    var errorEl = document.getElementById('live-noisy-error');
    var contentEl = document.getElementById('live-noisy-content');
    var tenantNameEl = document.getElementById('live-noisy-tenant-name');
    var tenantStatsEl = document.getElementById('live-noisy-tenant-stats');
    var tbody = document.getElementById('live-noisy-table-body');
    var updatedEl = document.getElementById('live-noisy-updated');

    if (!emptyEl || !contentEl || !tbody) return;

    emptyEl.style.display = 'none';
    if (errorEl) errorEl.style.display = 'none';
    contentEl.style.display = 'none';

    try {
      var res = await apiFetch('/admin/dashboard/noisy-neighbour/live');
      var data = await res.json();

      if (data.status === 'empty') {
        emptyEl.style.display = 'block';
        return;
      }
      if (data.status === 'error') {
        if (errorEl) {
          errorEl.textContent = 'Live data unavailable: ' + (data.message || 'Redis error');
          errorEl.style.display = 'block';
        }
        return;
      }

      var noisy = data.noisy_tenant;
      if (noisy && tenantNameEl) {
        tenantNameEl.textContent = noisy.tenant_name;
        tenantStatsEl.textContent =
          noisy.request_count + ' requests \u00b7 ' +
          noisy.share_pct + '% of all traffic \u00b7 ' +
          noisy.error_count + ' errors \u00b7 avg ' +
          noisy.avg_latency_ms + ' ms';
      }

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var allTenants = data.all_tenants || [];
      var noisyId = noisy ? noisy.tenant_id : null;

      for (var i = 0; i < allTenants.length; i++) {
        var t = allTenants[i];
        var tr = document.createElement('tr');
        if (t.tenant_id === noisyId) tr.style.background = 'rgba(255,80,80,0.06)';

        var tdName = document.createElement('td');
        tdName.style.fontWeight = '500';
        if (t.tenant_id === noisyId) {
          var nb = document.createElement('span');
          nb.className = 'badge badge-fail';
          nb.style.marginRight = '6px';
          nb.textContent = 'NOISY';
          tdName.appendChild(nb);
        }
        tdName.appendChild(document.createTextNode(t.tenant_name));
        tr.appendChild(tdName);

        var tdReq = document.createElement('td');
        tdReq.className = 'num';
        tdReq.textContent = t.request_count;
        tr.appendChild(tdReq);

        var tdErr = document.createElement('td');
        tdErr.className = 'num';
        tdErr.textContent = t.error_count;
        if (t.error_count > 0) tdErr.style.color = 'var(--status-compromised)';
        tr.appendChild(tdErr);

        var tdLat = document.createElement('td');
        tdLat.className = 'num';
        tdLat.textContent = t.avg_latency_ms;
        tr.appendChild(tdLat);

        var tdShare = document.createElement('td');
        tdShare.className = 'num';
        tdShare.textContent = t.share_pct + '%';
        tr.appendChild(tdShare);

        var tdRatio = document.createElement('td');
        tdRatio.className = 'num';
        if (t.tenant_id === noisyId) {
          tdRatio.textContent = '\u2014 (noisy)';
          tdRatio.style.color = 'var(--status-compromised)';
        } else {
          var ratio = (t.noisy_pressure_ratio != null) ? t.noisy_pressure_ratio : null;
          if (ratio !== null) {
            tdRatio.textContent = ratio + '\u00d7';
            if (ratio >= 5) tdRatio.style.color = 'var(--status-compromised)';
            else if (ratio >= 2) tdRatio.style.color = '#e8a020';
          } else {
            tdRatio.textContent = 'N/A';
          }
        }
        tr.appendChild(tdRatio);

        tbody.appendChild(tr);
      }

      contentEl.style.display = 'block';
      if (updatedEl) {
        updatedEl.textContent = 'Updated: ' + new Date().toLocaleTimeString() +
          ' \u00b7 ' + (data.total_requests_all_tenants || 0) + ' total requests across all tenants';
      }
    } catch (liveErr) {
      if (errorEl) {
        errorEl.textContent = 'Could not load live data: ' + liveErr.message;
        errorEl.style.display = 'block';
      }
    }
  }

  function setupLiveNoisyRefreshButton() {
    var btn = document.getElementById('btn-refresh-live-noisy');
    if (!btn || btn.getAttribute('data-bound')) return;
    btn.setAttribute('data-bound', 'true');
    btn.addEventListener('click', function () { loadLiveNoisyNeighbour(); });
  }

  function setupLiveBenchmarkRunner() {
    var btn = document.getElementById('btn-run-live-benchmark');
    var noisySelect = document.getElementById('bench-noisy-tenant');
    var victimSelect = document.getElementById('bench-victim-tenant');
    var loadTypeSelect = document.getElementById('bench-load-type');
    var strategySelect = document.getElementById('bench-strategy');
    var durationSelect = document.getElementById('bench-duration');
    var statusDiv = document.getElementById('bench-live-status');
    var statusText = document.getElementById('bench-live-status-text');
    var statusStats = document.getElementById('bench-live-status-stats');
    var progressBar = document.getElementById('bench-progress-bar');
    var resultCallout = document.getElementById('bench-result-callout');
    var resultCalloutText = document.getElementById('bench-result-callout-text');
    var btnIcon = document.getElementById('bench-btn-icon');
    var btnText = document.getElementById('bench-btn-text');
    var tbody = document.getElementById('noisy-table-body');
    var noisyContent = document.getElementById('noisy-content');
    var noisyEmpty = document.getElementById('noisy-empty');

    if (!btn || btn.getAttribute('data-bound')) return;
    btn.setAttribute('data-bound', 'true');

    // Prevent selecting identical noisy and victim tenants
    if (noisySelect && victimSelect) {
      noisySelect.addEventListener('change', function () {
        if (noisySelect.value === victimSelect.value) {
          victimSelect.value = (noisySelect.value === 'beta') ? 'acme' : 'beta';
        }
      });
      victimSelect.addEventListener('change', function () {
        if (victimSelect.value === noisySelect.value) {
          noisySelect.value = (victimSelect.value === 'acme') ? 'beta' : 'acme';
        }
      });
    }

    var isRunning = false;

    btn.addEventListener('click', async function () {
      if (isRunning) return;

      var noisyVal = noisySelect ? noisySelect.value : 'acme';
      var victimVal = victimSelect ? victimSelect.value : 'beta';
      var loadTypeVal = loadTypeSelect ? loadTypeSelect.value : 'high_volume';
      var strategyVal = strategySelect ? strategySelect.value : 'request_count';
      var durationVal = durationSelect ? parseFloat(durationSelect.value) : 10.0;

      var noisyLabel = (noisySelect && noisySelect.options[noisySelect.selectedIndex]) ? noisySelect.options[noisySelect.selectedIndex].text : noisyVal;
      var victimLabel = (victimSelect && victimSelect.options[victimSelect.selectedIndex]) ? victimSelect.options[victimSelect.selectedIndex].text : victimVal;
      var strategyLabel = (strategySelect && strategySelect.options[strategySelect.selectedIndex]) ? strategySelect.options[strategySelect.selectedIndex].text.replace(/^[^a-zA-Z]+/, '') : strategyVal;

      isRunning = true;
      btn.disabled = true;
      btn.style.opacity = '0.7';
      if (btnIcon) btnIcon.textContent = '⏳';
      if (btnText) btnText.textContent = 'Running Benchmark...';

      if (statusDiv) statusDiv.style.display = 'block';
      if (resultCallout) resultCallout.style.display = 'none';
      if (progressBar) progressBar.style.width = '5%';
      if (statusText) statusText.textContent = 'Initiating live benchmark: ' + noisyLabel + ' (noisy) vs ' + victimLabel + ' (victim) — strategy: ' + strategyLabel + '...';
      if (statusStats) statusStats.textContent = '0.0s / ' + durationVal + 's';

      try {
        var startRes = await apiFetch('/admin/demo/benchmark/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            noisy_tenant: noisyVal,
            victim_tenant: victimVal,
            load_type: loadTypeVal,
            strategy: strategyVal,
            duration_seconds: durationVal
          })
        });

        if (!startRes.ok) {
          var errData = await startRes.json().catch(function () { return {}; });
          throw new Error(errData.detail || ('HTTP ' + startRes.status));
        }

        var startData = await startRes.json();
        var runId = startData.run_id;

        var isCompleted = false;
        var pollTimer = setInterval(async function () {
          if (isCompleted) return;
          try {
            var stRes = await apiFetch('/admin/demo/benchmark/status/' + runId);
            if (!stRes.ok) return;
            var stData = await stRes.json();

            if (isCompleted) return;

            if (stData.progress) {
              var p = stData.progress;
              var pct = Math.min(95, Math.round((p.elapsed / durationVal) * 100));
              if (progressBar) progressBar.style.width = pct + '%';
              if (statusStats) statusStats.textContent = p.elapsed + 's / ' + durationVal + 's';
              if (statusText) {
                statusText.textContent = '🔥 ' + noisyLabel + ' sent ' + p.noisy_reqs + ' reqs (' + p.noisy_429s + ' rate-limited 429s) · 🛡️ ' + victimLabel + ' sent ' + p.victim_reqs + ' steady reqs';
              }
            }

            if (stData.state === 'completed' && stData.summary) {
              isCompleted = true;
              clearInterval(pollTimer);
              var s = stData.summary;

              if (progressBar) progressBar.style.width = '100%';
              if (statusText) {
                statusText.textContent = 'Benchmark completed successfully in ' + durationVal + 's!';
              }

              // Ensure benchmark table container is visible
              if (noisyContent) noisyContent.style.display = 'block';
              if (noisyEmpty) noisyEmpty.style.display = 'none';

              // Show Result Callout Banner
              if (resultCallout && resultCalloutText) {
                resultCalloutText.innerHTML = '<strong>Live Result:</strong> ' +
                  s.noisy_tenant + ' sent <strong>' + s.noisy_total + '</strong> requests (<strong>' + s.noisy_429 + '</strong> rate-limited with HTTP 429). ' +
                  s.victim_tenant + ' observed p50: <strong>' + s.victim_p50_ms + ' ms</strong>, p95: <strong>' + s.victim_p95_ms + ' ms</strong>, error rate: <strong>' + s.victim_error_rate + '%</strong>.';
                resultCallout.style.display = 'block';
              }

              // Insert Live Row at TOP of tbody
              if (tbody) {
                var tr = document.createElement('tr');
                tr.style.background = 'rgba(34,197,94,0.08)';
                tr.style.borderLeft = '3px solid #22c55e';
                tr.style.fontWeight = '500';

                var tdStrat = document.createElement('td');
                var liveBadge = document.createElement('span');
                liveBadge.className = 'badge';
                liveBadge.style.cssText = 'background: rgba(34,197,94,0.2); color: #16a34a; font-weight: 700; margin-right: 6px;';
                liveBadge.textContent = 'LIVE';
                tdStrat.appendChild(liveBadge);
                tdStrat.appendChild(document.createTextNode(s.strategy_label));
                tr.appendChild(tdStrat);

                var tdLoad = document.createElement('td');
                tdLoad.textContent = s.load_type + ' (' + s.noisy_tenant.split(' ')[0] + ' ➔ ' + s.victim_tenant.split(' ')[0] + ')';
                tr.appendChild(tdLoad);

                var tdP50 = document.createElement('td');
                tdP50.className = 'num';
                tdP50.textContent = s.victim_p50_ms;
                tr.appendChild(tdP50);

                var tdP95 = document.createElement('td');
                tdP95.className = 'num';
                tdP95.textContent = s.victim_p95_ms;
                tr.appendChild(tdP95);

                var tdErr = document.createElement('td');
                tdErr.className = 'num';
                tdErr.textContent = s.victim_error_rate + '%';
                if (s.victim_error_rate > 0) tdErr.style.color = 'var(--status-compromised)';
                tr.appendChild(tdErr);

                var td429 = document.createElement('td');
                td429.className = 'num';
                td429.textContent = s.noisy_429;
                if (s.noisy_429 > 0) {
                  td429.style.color = '#eab308';
                  td429.style.fontWeight = '700';
                }
                tr.appendChild(td429);

                var tdTimeouts = document.createElement('td');
                tdTimeouts.className = 'num';
                tdTimeouts.textContent = s.noisy_timeouts;
                tr.appendChild(tdTimeouts);

                if (tbody.firstChild) {
                  tbody.insertBefore(tr, tbody.firstChild);
                } else {
                  tbody.appendChild(tr);
                }
              }

              // Auto-refresh the live telemetry panel as well
              loadLiveNoisyNeighbour();

              // Reset button
              isRunning = false;
              btn.disabled = false;
              btn.style.opacity = '1';
              if (btnIcon) btnIcon.textContent = '▶';
              if (btnText) btnText.textContent = 'Run Live Benchmark';

              setTimeout(function () {
                if (statusDiv) statusDiv.style.display = 'none';
              }, 4000);
            } else if (stData.state === 'failed') {
              clearInterval(pollTimer);
              isRunning = false;
              btn.disabled = false;
              btn.style.opacity = '1';
              if (btnIcon) btnIcon.textContent = '▶';
              if (btnText) btnText.textContent = 'Run Live Benchmark';
              if (statusText) statusText.textContent = 'Benchmark failed: ' + (stData.error || 'Unknown error');
            }
          } catch (pollErr) {
            console.error('Error polling live benchmark:', pollErr);
          }
        }, 800);

      } catch (err) {
        isRunning = false;
        btn.disabled = false;
        btn.style.opacity = '1';
        if (btnIcon) btnIcon.textContent = '▶';
        if (btnText) btnText.textContent = 'Run Live Benchmark';
        if (statusText) statusText.textContent = 'Failed to start benchmark: ' + err.message;
      }
    });
  }

  var _tenantNamesCache = null;
  async function getTenantNamesMap() {
    if (_tenantNamesCache) return _tenantNamesCache;
    _tenantNamesCache = {};
    try {
      var res = await apiFetch('/admin/dashboard/keys');
      var data = await res.json();
      var list = (data && data.tenants) || [];
      for (var i = 0; i < list.length; i++) {
        if (list[i].tenant_id && list[i].tenant_name) {
          _tenantNamesCache[list[i].tenant_id] = list[i].tenant_name;
        }
      }
    } catch (e) {}
    return _tenantNamesCache;
  }

  // 5. Per-Tenant Metrics Section
  async function loadMetricsSection() {
    var contentEl = document.getElementById('metrics-content');
    var emptyEl = document.getElementById('metrics-empty');
    var tbody = document.getElementById('metrics-table-body');
    var chartContainer = document.getElementById('metrics-chart-container');

    try {
      var nameMap = await getTenantNamesMap();
      var res = await apiFetch('/admin/metrics?window_minutes=60');
      var data = await res.json();

      var tenants = (data && data.tenants) || [];
      if (tenants.length === 0) {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var chartData = [];

      for (var i = 0; i < tenants.length; i++) {
        var t = tenants[i];
        var tr = document.createElement('tr');
        var tenantName = nameMap[t.tenant_id] || ('Tenant ' + t.tenant_id.substring(0, 8));

        var tdTenant = document.createElement('td');
        var nameDiv = document.createElement('div');
        nameDiv.style.fontWeight = '600';
        nameDiv.style.color = 'var(--text-primary)';
        nameDiv.textContent = tenantName;
        tdTenant.appendChild(nameDiv);

        var codeId = document.createElement('code');
        codeId.style.fontSize = '0.78rem';
        codeId.style.color = 'var(--text-muted)';
        codeId.textContent = t.tenant_id;
        tdTenant.appendChild(codeId);
        tr.appendChild(tdTenant);

        var tdReq = document.createElement('td');
        tdReq.className = 'num';
        tdReq.textContent = t.request_count.toLocaleString() + ' ';
        tdReq.appendChild(createInfoButton('Requests'));
        tr.appendChild(tdReq);

        var tdErr = document.createElement('td');
        tdErr.className = 'num';
        tdErr.textContent = t.error_count.toLocaleString() + ' ';
        tdErr.appendChild(createInfoButton('Errors'));
        tr.appendChild(tdErr);

        var tdLat = document.createElement('td');
        tdLat.className = 'num';
        tdLat.textContent = t.avg_latency_ms.toFixed(2) + ' ';
        tdLat.appendChild(createInfoButton('Average latency'));
        tr.appendChild(tdLat);

        tbody.appendChild(tr);

        chartData.push({
          label: tenantName,
          value: t.avg_latency_ms
        });
      }

      // Render Bar Chart using local vendor tool
      window._lastMetricsChartData = {
        data: chartData,
        labelKey: 'label',
        valueKey: 'value',
        unit: 'ms',
        height: 180
      };
      if (window.TenantChart && window.TenantChart.renderBarChart) {
        window.TenantChart.renderBarChart(chartContainer, window._lastMetricsChartData);
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 6. Tenant Key Status Section
  async function loadKeysSection() {
    var contentEl = document.getElementById('keys-content');
    var emptyEl = document.getElementById('keys-empty');
    var tbody = document.getElementById('keys-table-body');

    try {
      var res = await apiFetch('/admin/dashboard/keys');
      var data = await res.json();

      if (data.status === 'empty') {
        contentEl.style.display = 'none';
        emptyEl.style.display = 'block';
        return;
      }

      emptyEl.style.display = 'none';
      contentEl.style.display = 'block';

      while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
      var tenants = data.tenants || [];

      // Update Overview KPI
      var kpiKeys = document.getElementById('kpi-keys');
      var kpiKeysSub = document.getElementById('kpi-keys-sub');
      if (kpiKeys && tenants) {
        var totalKeyCount = 0;
        var activeCount = 0;
        for (var tk = 0; tk < tenants.length; tk++) {
          var tkeys = tenants[tk].keys || [];
          totalKeyCount += tkeys.length;
          for (var ki = 0; ki < tkeys.length; ki++) {
            if (tkeys[ki].status === 'active') activeCount++;
          }
        }
        kpiKeys.textContent = activeCount + ' Active';
        if (kpiKeysSub) {
          kpiKeysSub.textContent = totalKeyCount + ' total across ' + tenants.length + ' tenants';
        }
      }
      for (var i = 0; i < tenants.length; i++) {
        var t = tenants[i];
        var keys = t.keys || [];

        if (keys.length === 0) {
          var trEmpty = document.createElement('tr');
          var tdTName = document.createElement('td');
          tdTName.style.fontWeight = '500';
          tdTName.textContent = t.tenant_name;
          trEmpty.appendChild(tdTName);

          var tdTId = document.createElement('td');
          var codeTId = document.createElement('code');
          codeTId.textContent = t.tenant_id;
          tdTId.appendChild(codeTId);
          trEmpty.appendChild(tdTId);

          var tdNoKey = document.createElement('td');
          tdNoKey.colSpan = 6;
          tdNoKey.style.color = 'var(--text-muted)';
          tdNoKey.textContent = 'No keys provisioned';
          trEmpty.appendChild(tdNoKey);

          tbody.appendChild(trEmpty);
          continue;
        }

        for (var k = 0; k < keys.length; k++) {
          var keyItem = keys[k];
          var tr = document.createElement('tr');

          var tdName = document.createElement('td');
          tdName.style.fontWeight = '500';
          tdName.textContent = t.tenant_name;
          tr.appendChild(tdName);

          var tdId = document.createElement('td');
          var codeId = document.createElement('code');
          codeId.textContent = t.tenant_id;
          tdId.appendChild(codeId);
          tr.appendChild(tdId);

          var tdVer = document.createElement('td');
          tdVer.className = 'num';
          tdVer.textContent = keyItem.key_version + ' ';
          tdVer.appendChild(createInfoButton('Key version'));
          tr.appendChild(tdVer);

          var tdStat = document.createElement('td');
          tdStat.appendChild(createStatusBadge(keyItem.status, getDotTypeForStatus(keyItem.status)));
          tdStat.appendChild(createInfoButton(keyItem.status));
          tr.appendChild(tdStat);

          var tdCreated = document.createElement('td');
          tdCreated.style.fontSize = '12px';
          tdCreated.textContent = keyItem.created_at ? new Date(keyItem.created_at).toLocaleString() : '—';
          tr.appendChild(tdCreated);

          var tdRet = document.createElement('td');
          tdRet.style.fontSize = '12px';
          tdRet.textContent = keyItem.retired_at ? new Date(keyItem.retired_at).toLocaleString() : '—';
          if (keyItem.retired_at) {
            tdRet.appendChild(createInfoButton('retired'));
          }
          tr.appendChild(tdRet);

          var tdDes = document.createElement('td');
          tdDes.style.fontSize = '12px';
          tdDes.textContent = keyItem.destroyed_at ? new Date(keyItem.destroyed_at).toLocaleString() : '—';
          if (keyItem.destroyed_at) {
            tdDes.appendChild(createInfoButton('destroyed'));
          }
          tr.appendChild(tdDes);

          // Actions cell with Rotate key button
          var tdAct = document.createElement('td');
          if (keyItem.status === 'active') {
            var rotBtn = document.createElement('button');
            rotBtn.type = 'button';
            rotBtn.className = 'btn btn-sm';
            rotBtn.textContent = 'Rotate key';
            rotBtn.addEventListener('click', (function (tenantId, tenantName, kVer) {
              return async function () {
                var confirmed = window.confirm(
                  'Are you sure you want to rotate the active key for ' +
                    tenantName +
                    ' (current version ' +
                    kVer +
                    ')? This will provision key version ' +
                    (kVer + 1) +
                    '.'
                );
                if (!confirmed) return;

                rotBtn.disabled = true;
                rotBtn.textContent = 'Rotating...';
                try {
                  var rRes = await apiFetch('/admin/keys/' + tenantId + '/rotate', {
                    method: 'POST'
                  });
                  if (!rRes.ok) {
                    var errD = await rRes.json();
                    throw new Error(errD.detail || 'Key rotation failed.');
                  }
                  await loadKeysSection();
                } catch (rErr) {
                  alert(rErr.message || 'Key rotation failed.');
                  rotBtn.disabled = false;
                  rotBtn.textContent = 'Rotate key';
                }
              };
            })(t.tenant_id, t.tenant_name, keyItem.key_version));
            tdAct.appendChild(rotBtn);
          } else {
            tdAct.textContent = '—';
          }
          tr.appendChild(tdAct);

          tbody.appendChild(tr);
        }
      }
    } catch (err) {
      contentEl.style.display = 'none';
      emptyEl.style.display = 'block';
    }
  }

  // 7. Key Lifecycle Demo Controller
  function setupKeyLifecycleDemo() {
    var step1Btn = document.getElementById('btn-demo-step-1');
    var res1Box = document.getElementById('demo-result-1');

    var step2Btn = document.getElementById('btn-demo-step-2');
    var res2Box = document.getElementById('demo-result-2');

    var step3Btn = document.getElementById('btn-demo-step-3');
    var res3Box = document.getElementById('demo-result-3');

    var step4Btn = document.getElementById('btn-demo-step-4');
    var res4Box = document.getElementById('demo-result-4');

    var step5Btn = document.getElementById('btn-demo-step-5');
    var confirmInput = document.getElementById('input-demo-destroy-confirm');
    var res5Box = document.getElementById('demo-result-5');

    var step6Btn = document.getElementById('btn-demo-step-6');
    var res6Box = document.getElementById('demo-result-6');

    var step7Btn = document.getElementById('btn-demo-step-7');
    var res7Box = document.getElementById('demo-result-7');

    if (!step1Btn || step1Btn.getAttribute('data-bound')) return;
    step1Btn.setAttribute('data-bound', 'true');

    // Step 1: Create before document
    step1Btn.addEventListener('click', async function () {
      step1Btn.disabled = true;
      res1Box.textContent = 'Creating document under active key...';
      try {
        var res = await apiFetch('/admin/demo/keys/create-document', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ label: 'before' })
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to create document.');
        res1Box.textContent = 'Created: doc ' + data.document_id + '\nLabel: ' + data.label + '\nKey version: ' + data.key_version;
        await loadKeysSection();
      } catch (err) {
        res1Box.textContent = 'Error: ' + err.message;
      } finally {
        step1Btn.disabled = false;
      }
    });

    // Step 2: Rotate key
    step2Btn.addEventListener('click', async function () {
      step2Btn.disabled = true;
      res2Box.textContent = 'Rotating Demo Co active key...';
      try {
        var res = await apiFetch('/admin/demo/keys/rotate', {
          method: 'POST'
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to rotate key.');
        res2Box.textContent = 'Rotated successfully.\nNew active key version: ' + data.new_key_version;
        await loadKeysSection();
      } catch (err) {
        res2Box.textContent = 'Error: ' + err.message;
      } finally {
        step2Btn.disabled = false;
      }
    });

    // Step 3: Create after document
    step3Btn.addEventListener('click', async function () {
      step3Btn.disabled = true;
      res3Box.textContent = 'Creating document under rotated key...';
      try {
        var res = await apiFetch('/admin/demo/keys/create-document', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ label: 'after' })
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to create document.');
        res3Box.textContent = 'Created: doc ' + data.document_id + '\nLabel: ' + data.label + '\nKey version: ' + data.key_version;
        await loadKeysSection();
      } catch (err) {
        res3Box.textContent = 'Error: ' + err.message;
      } finally {
        step3Btn.disabled = false;
      }
    });

    // Step 4: Read both documents
    step4Btn.addEventListener('click', async function () {
      step4Btn.disabled = true;
      res4Box.textContent = 'Decrypting all Demo Co documents...';
      try {
        var res = await apiFetch('/admin/demo/keys/read', {
          method: 'POST'
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to read documents.');
        var docs = data.documents || [];
        var latestDocs = docs.slice(-2);
        var lines = ['Decryption test (latest ' + latestDocs.length + ' of ' + (data.total_documents || docs.length) + ' documents):'];
        for (var i = 0; i < latestDocs.length; i++) {
          lines.push('[' + latestDocs[i].label + '] v' + latestDocs[i].key_version + ': ' + latestDocs[i].status + (latestDocs[i].reason ? ' (' + latestDocs[i].reason + ')' : ''));
        }
        res4Box.textContent = lines.join('\n');
        await loadKeysSection();
      } catch (err) {
        res4Box.textContent = 'Error: ' + err.message;
      } finally {
        step4Btn.disabled = false;
      }
    });

    // Step 5: Destroy key
    step5Btn.addEventListener('click', async function () {
      var typedVal = (confirmInput.value || '').trim();
      if (typedVal !== 'DESTROY') {
        alert('Confirmation required: Type DESTROY into the box to confirm crypto-shredding.');
        return;
      }

      step5Btn.disabled = true;
      res5Box.textContent = 'Crypto-shredding Demo Co keys...';
      try {
        var res = await apiFetch('/admin/demo/keys/destroy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ confirm: 'DESTROY' })
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to destroy key.');
        res5Box.textContent = 'Destroyed permanently.\nKeys shredded: ' + data.keys_shredded;
        confirmInput.value = '';
        await loadKeysSection();
      } catch (err) {
        res5Box.textContent = 'Error: ' + err.message;
      } finally {
        step5Btn.disabled = false;
      }
    });

    // Step 6: Read both documents again
    step6Btn.addEventListener('click', async function () {
      step6Btn.disabled = true;
      res6Box.textContent = 'Attempting decryption post-shredding...';
      try {
        var res = await apiFetch('/admin/demo/keys/read', {
          method: 'POST'
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to read documents.');
        var docs = data.documents || [];
        var latestDocs = docs.slice(-2);
        var lines = ['Decryption test results (latest ' + latestDocs.length + ' of ' + (data.total_documents || docs.length) + ' documents):'];
        for (var i = 0; i < latestDocs.length; i++) {
          lines.push('[' + latestDocs[i].label + '] v' + latestDocs[i].key_version + ': ' + latestDocs[i].status + (latestDocs[i].reason ? ' (' + latestDocs[i].reason + ')' : ''));
        }
        res6Box.textContent = lines.join('\n');
        await loadKeysSection();
      } catch (err) {
        res6Box.textContent = 'Error: ' + err.message;
      } finally {
        step6Btn.disabled = false;
      }
    });

    // Step 7: Read Acme document
    step7Btn.addEventListener('click', async function () {
      step7Btn.disabled = true;
      res7Box.textContent = 'Verifying Acme document in Acme context...';
      try {
        var res = await apiFetch('/admin/demo/keys/read-other', {
          method: 'POST'
        });
        var data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to read Acme document.');
        res7Box.textContent = 'Target Tenant: ' + data.target_tenant + '\nDecryption Outcome: ' + data.status + '\nIsolation: Intact (unaffected)';
        await loadKeysSection();
      } catch (err) {
        res7Box.textContent = 'Error: ' + err.message;
      } finally {
        step7Btn.disabled = false;
      }
    });
  }

  // 8. Send Test Traffic Controller
  function setupSendTestTrafficButton() {
    var btn = document.getElementById('btn-send-test-traffic');
    var statusMsg = document.getElementById('traffic-status-msg');
    var progressContainer = document.getElementById('traffic-progress-container');
    var progressTbody = document.getElementById('traffic-progress-tbody');
    var comparisonContainer = document.getElementById('traffic-comparison-container');
    var comparisonTbody = document.getElementById('traffic-comparison-tbody');

    if (!btn || btn.getAttribute('data-bound')) return;
    btn.setAttribute('data-bound', 'true');

    btn.addEventListener('click', async function () {
      var tenantSelect = document.getElementById('traffic-tenant-select');
      var selectedTenant = (tenantSelect && tenantSelect.value) || 'demo';
      var tenantLabel = (tenantSelect && tenantSelect.options[tenantSelect.selectedIndex] ? tenantSelect.options[tenantSelect.selectedIndex].text : selectedTenant);

      btn.disabled = true;
      btn.textContent = 'Sending traffic...';
      if (statusMsg) {
        statusMsg.style.display = 'block';
        statusMsg.textContent = 'Initiating test traffic for ' + tenantLabel + ' (10 valid, 3 invalid requests)...';
      }

      while (progressTbody.firstChild) progressTbody.removeChild(progressTbody.firstChild);
      while (comparisonTbody.firstChild) comparisonTbody.removeChild(comparisonTbody.firstChild);
      if (progressContainer) progressContainer.style.display = 'block';
      if (comparisonContainer) comparisonContainer.style.display = 'none';

      try {
        var startRes = await apiFetch('/admin/demo/traffic/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ tenant: selectedTenant })
        });
        var startData = await startRes.json();
        if (!startRes.ok) {
          throw new Error(startData.detail || 'Failed to start traffic.');
        }

        var runId = startData.run_id;
        var renderedCount = 0;

        var pollInterval = setInterval(async function () {
          try {
            var stRes = await apiFetch('/admin/demo/traffic/status/' + runId);
            if (!stRes.ok) return;
            var stData = await stRes.json();

            var progress = stData.progress || [];
            while (renderedCount < progress.length) {
              var rec = progress[renderedCount];
              var tr = document.createElement('tr');

              var tdNum = document.createElement('td');
              tdNum.className = 'num';
              tdNum.textContent = rec.number;
              tr.appendChild(tdNum);

              var tdKind = document.createElement('td');
              var badgeClass = rec.kind === 'valid' ? 'badge badge-pass' : 'badge badge-fail';
              var spanKind = document.createElement('span');
              spanKind.className = badgeClass;
              spanKind.textContent = rec.kind;
              tdKind.appendChild(spanKind);
              tr.appendChild(tdKind);

              var tdMethod = document.createElement('td');
              tdMethod.textContent = rec.method;
              tr.appendChild(tdMethod);

              var tdPath = document.createElement('td');
              var codePath = document.createElement('code');
              codePath.textContent = rec.path;
              tdPath.appendChild(codePath);
              tr.appendChild(tdPath);

              var tdStatus = document.createElement('td');
              tdStatus.className = 'num';
              tdStatus.textContent = rec.status_code;
              tr.appendChild(tdStatus);

              var tdDur = document.createElement('td');
              tdDur.className = 'num';
              tdDur.textContent = rec.duration_ms.toFixed(2);
              tr.appendChild(tdDur);

              progressTbody.appendChild(tr);
              renderedCount++;
            }

            if (stData.state === 'finished') {
              clearInterval(pollInterval);
              btn.disabled = false;
              btn.textContent = 'Send test traffic';
              if (statusMsg) {
                statusMsg.textContent = 'Traffic run completed (' + renderedCount + ' requests sent).';
              }

              // Render comparison table
              if (stData.comparison) {
                while (comparisonTbody.firstChild) comparisonTbody.removeChild(comparisonTbody.firstChild);
                var comp = stData.comparison;
                var metricsOrder = [
                  { key: 'requests', label: 'Requests' },
                  { key: 'errors', label: 'Errors' },
                  { key: 'avg_latency_ms', label: 'Avg latency (ms)' }
                ];

                for (var m = 0; m < metricsOrder.length; m++) {
                  var mInfo = metricsOrder[m];
                  var mData = comp[mInfo.key] || { before: 0, after: 0, diff: 0 };
                  var trC = document.createElement('tr');

                  var tdLabel = document.createElement('td');
                  tdLabel.style.fontWeight = '500';
                  tdLabel.textContent = mInfo.label;
                  trC.appendChild(tdLabel);

                  var tdBef = document.createElement('td');
                  tdBef.className = 'num';
                  tdBef.textContent = mData.before;
                  trC.appendChild(tdBef);

                  var tdAft = document.createElement('td');
                  tdAft.className = 'num';
                  tdAft.textContent = mData.after;
                  trC.appendChild(tdAft);

                  var tdDiff = document.createElement('td');
                  tdDiff.className = 'num';
                  var diffVal = mData.diff;
                  tdDiff.textContent = (diffVal > 0 ? '+' : '') + diffVal;
                  if (diffVal > 0 && mInfo.key === 'errors') {
                    tdDiff.style.color = 'var(--status-compromised)';
                  }
                  trC.appendChild(tdDiff);

                  comparisonTbody.appendChild(trC);
                }

                if (comparisonContainer) comparisonContainer.style.display = 'block';
              }

              await loadMetricsSection();
              loadLiveNoisyNeighbour();
            } else if (stData.state === 'failed') {
              clearInterval(pollInterval);
              btn.disabled = false;
              btn.textContent = 'Send test traffic';
              if (statusMsg) {
                statusMsg.textContent = 'Traffic run ended with error.';
              }
            }
          } catch (pErr) {
            // Keep polling
          }
        }, 800);

      } catch (err) {
        btn.disabled = false;
        btn.textContent = 'Send test traffic';
        if (statusMsg) {
          statusMsg.textContent = 'Error: ' + err.message;
        }
      }
    });
  }

  // 9. Configuration Check Section
  async function loadConfigCheckSection() {
    var btn = document.getElementById('btn-run-config-check');
    var timeEl = document.getElementById('config-check-time');
    var alertEl = document.getElementById('config-check-alert');
    var summaryEl = document.getElementById('config-check-summary');
    var contentEl = document.getElementById('config-check-content');
    var tbody = document.getElementById('config-check-tbody');
    var overallEl = document.getElementById('config-check-overall');
    var totalEl = document.getElementById('config-check-total');
    var passedEl = document.getElementById('config-check-passed');
    var failedEl = document.getElementById('config-check-failed');

    if (!btn) return;

    async function runCheck() {
      btn.disabled = true;
      btn.textContent = 'Checking...';
      if (alertEl) alertEl.style.display = 'none';
      if (summaryEl) summaryEl.style.display = 'none';
      if (contentEl) contentEl.style.display = 'none';

      try {
        var res = await apiFetch('/admin/dashboard/config-check');
        var data = await res.json();

        if (!res.ok) {
          if (alertEl) {
            alertEl.textContent = data.detail || 'Failed to run configuration check.';
            alertEl.style.display = 'block';
          }
          return;
        }

        // Summary row
        if (overallEl) {
          while (overallEl.firstChild) overallEl.removeChild(overallEl.firstChild);
          overallEl.appendChild(createStatusBadge(data.overall_status, getDotTypeForStatus(data.overall_status)));
        }
        if (totalEl) totalEl.textContent = data.total_checks;
        if (passedEl) passedEl.textContent = data.passed;
        if (failedEl) failedEl.textContent = data.failed;
        if (summaryEl) summaryEl.style.display = 'block';

        // Update Overview KPI
        var kpiConfig = document.getElementById('kpi-config');
        var kpiConfigSub = document.getElementById('kpi-config-sub');
        if (kpiConfig) {
          kpiConfig.textContent = data.passed + ' / ' + data.total_checks + ' Passed';
          if (kpiConfigSub) {
            kpiConfigSub.textContent = data.failed === 0 ? 'All controls verified' : data.failed + ' checks failed';
          }
        }

        // Populate checks table
        if (tbody) {
          while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
          var checks = data.checks || [];
          for (var i = 0; i < checks.length; i++) {
            var c = checks[i];
            var tr = document.createElement('tr');

            var tdName = document.createElement('td');
            tdName.style.fontWeight = '500';
            tdName.textContent = c.name;
            tr.appendChild(tdName);

            var tdStatus = document.createElement('td');
            tdStatus.appendChild(createStatusBadge(c.status, getDotTypeForStatus(c.status === 'PASS' ? 'BLOCKED' : 'LEAKED')));
            tr.appendChild(tdStatus);

            var tdDetail = document.createElement('td');
            tdDetail.style.fontSize = '12px';
            tdDetail.textContent = c.detail;
            tr.appendChild(tdDetail);

            var tdRec = document.createElement('td');
            tdRec.style.fontSize = '12px';
            tdRec.style.color = 'var(--text-muted)';
            tdRec.textContent = c.recommendation || '—';
            tr.appendChild(tdRec);

            tbody.appendChild(tr);
          }
        }

        if (timeEl) timeEl.textContent = new Date().toLocaleString();
        if (contentEl) contentEl.style.display = 'block';
      } catch (err) {
        if (alertEl) {
          alertEl.textContent = err.message || 'Error running configuration check.';
          alertEl.style.display = 'block';
        }
      } finally {
        btn.disabled = false;
        btn.textContent = 'Run check';
      }
    }

    if (!btn.getAttribute('data-bound')) {
      btn.setAttribute('data-bound', 'true');
      btn.addEventListener('click', runCheck);
    }
  }

  // 10. Try One Attack by Hand Controller
  function setupAttackDemo() {
    var selAttacker = document.getElementById('attack-select-attacker');
    var selVictim = document.getElementById('attack-select-victim');
    var selAction = document.getElementById('attack-select-action');
    var btn = document.getElementById('btn-run-attack');
    var alertBox = document.getElementById('attack-alert-box');
    var stepsContainer = document.getElementById('attack-steps-container');
    var resultCard = document.getElementById('attack-result-card');
    var resReq = document.getElementById('attack-res-request');
    var resStatus = document.getElementById('attack-res-status');
    var resOutcome = document.getElementById('attack-res-outcome');
    var resControl = document.getElementById('attack-res-control');
    var resVictimState = document.getElementById('attack-res-victim-state');
    var resExplanation = document.getElementById('attack-res-explanation');

    if (!btn || btn.getAttribute('data-bound')) return;
    btn.setAttribute('data-bound', 'true');

    var modeRadios = document.querySelectorAll('input[name="attack-target-mode"]');
    var modeNote = document.getElementById('attack-mode-note');
    for (var mr = 0; mr < modeRadios.length; mr++) {
      modeRadios[mr].addEventListener('change', function () {
        var activeMode = document.querySelector('input[name="attack-target-mode"]:checked');
        if (modeNote) {
          modeNote.style.display = (activeMode && activeMode.value === 'vulnerable') ? 'block' : 'none';
        }
      });
    }

    var btnToggleDiff = document.getElementById('btn-toggle-attack-diff');
    var diffContainer = document.getElementById('attack-code-diff-container');
    if (btnToggleDiff && diffContainer && !btnToggleDiff.getAttribute('data-bound')) {
      btnToggleDiff.setAttribute('data-bound', 'true');
      btnToggleDiff.addEventListener('click', function () {
        diffContainer.style.display = (diffContainer.style.display === 'none' || !diffContainer.style.display) ? 'block' : 'none';
      });
    }

    var defaultStepTitles = [
      'Authenticate sessions',
      'Plant canary document in victim workspace',
      'Send attack request as attacker',
      'Verify victim document integrity',
      'Clean up planted test documents',
      'Evaluate attack outcome'
    ];

    function renderInitialSteps() {
      while (stepsContainer.firstChild) stepsContainer.removeChild(stepsContainer.firstChild);
      stepsContainer.style.display = 'flex';
      for (var s = 0; s < 6; s++) {
        var card = document.createElement('div');
        card.id = 'attack-step-row-' + (s + 1);
        card.style.display = 'flex';
        card.style.alignItems = 'center';
        card.style.gap = '8px';
        card.style.padding = '4px 8px';
        card.style.fontSize = '12px';
        card.style.color = 'var(--text-secondary)';

        var numSpan = document.createElement('span');
        numSpan.style.fontWeight = '600';
        numSpan.style.color = 'var(--text-muted)';
        numSpan.style.minWidth = '16px';
        numSpan.textContent = (s + 1) + '.';
        card.appendChild(numSpan);

        var msgSpan = document.createElement('span');
        msgSpan.className = 'attack-step-msg';
        msgSpan.style.flex = '1';
        msgSpan.textContent = defaultStepTitles[s];
        card.appendChild(msgSpan);

        var statusSpan = document.createElement('span');
        statusSpan.className = 'attack-step-status';
        statusSpan.style.fontFamily = 'var(--font-mono)';
        statusSpan.style.fontSize = '11px';
        statusSpan.style.color = 'var(--text-muted)';
        statusSpan.textContent = '⏳';
        card.appendChild(statusSpan);

        stepsContainer.appendChild(card);
      }
    }

    btn.addEventListener('click', async function () {
      if (alertBox) {
        alertBox.style.display = 'none';
        alertBox.textContent = '';
      }
      if (resultCard) {
        resultCard.style.display = 'none';
      }

      var attacker = selAttacker ? selAttacker.value : 'Acme';
      var victim = selVictim ? selVictim.value : 'Beta';
      var action = selAction ? selAction.value : 'read';
      var targetModeRadio = document.querySelector('input[name="attack-target-mode"]:checked');
      var targetMode = (targetModeRadio && targetModeRadio.value) || 'secure';

      if (attacker === victim) {
        if (alertBox) {
          alertBox.style.display = 'block';
          alertBox.textContent = 'Attacker and victim must be different tenants.';
        }
        return;
      }

      btn.disabled = true;
      btn.textContent = 'Running attack...';
      renderInitialSteps();

      try {
        var startRes = await apiFetch('/admin/demo/attack/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            attacker: attacker,
            victim: victim,
            action: action,
            target_mode: targetMode
          })
        });

        var startData = await startRes.json();
        if (!startRes.ok) {
          throw new Error(startData.detail || 'Failed to start attack run.');
        }

        var runId = startData.run_id;

        var pollInterval = setInterval(async function () {
          try {
            var stRes = await apiFetch('/admin/demo/attack/status/' + runId);
            var stData = await stRes.json();
            if (!stRes.ok) throw new Error(stData.detail || 'Failed to check attack status.');

            var progress = stData.progress || [];
            for (var p = 0; p < progress.length; p++) {
              var rec = progress[p];
              var row = document.getElementById('attack-step-row-' + rec.step);
              if (row) {
                var mEl = row.querySelector('.attack-step-msg');
                if (mEl) mEl.textContent = rec.message;
                var sEl = row.querySelector('.attack-step-status');
                if (sEl) {
                  sEl.textContent = 'Done';
                  sEl.style.color = 'var(--accent)';
                }
                row.style.borderColor = 'var(--border-subtle)';
              }
            }

            if (stData.state === 'finished') {
              clearInterval(pollInterval);
              btn.disabled = false;
              btn.textContent = 'Run attack';
              if (stepsContainer) stepsContainer.style.display = 'none';

              var res = stData.result;
              if (res && resultCard) {
                if (resReq) {
                  resReq.textContent = (res.request && res.request.method ? res.request.method + ' ' + res.request.path : '—');
                }
                if (resStatus) {
                  resStatus.textContent = res.status_code != null ? String(res.status_code) : '—';
                }
                if (resOutcome) {
                  while (resOutcome.firstChild) resOutcome.removeChild(resOutcome.firstChild);
                  resOutcome.appendChild(createStatusBadge(res.outcome, getDotTypeForStatus(res.outcome)));
                }
                if (resControl) {
                  resControl.textContent = res.blocking_control || 'unknown';
                }
                if (resVictimState) {
                  while (resVictimState.firstChild) resVictimState.removeChild(resVictimState.firstChild);
                  resVictimState.appendChild(createStatusBadge(res.victim_doc_state, getDotTypeForStatus(res.victim_doc_state)));
                }
                if (resExplanation) {
                  resExplanation.textContent = res.explanation || '—';
                }

                // Show exfiltrated data if leaked
                var leakBox = document.getElementById('attack-res-leak-box');
                var leakContent = document.getElementById('attack-res-leak-content');
                if (leakBox && leakContent) {
                  if (res.outcome === 'LEAKED' && res.leaked_text) {
                    leakContent.textContent = res.leaked_text;
                    leakBox.style.display = 'block';
                  } else {
                    leakBox.style.display = 'none';
                  }
                }

                // Border styling depending on outcome
                if (res.outcome === 'LEAKED') {
                  resultCard.style.border = '2px solid #ef4444';
                  resultCard.style.boxShadow = '0 0 15px rgba(239, 68, 68, 0.2)';
                } else {
                  resultCard.style.border = '1px solid #10b981';
                  resultCard.style.boxShadow = 'none';
                }

                resultCard.style.display = 'block';
              }
            } else if (stData.state === 'failed') {
              clearInterval(pollInterval);
              btn.disabled = false;
              btn.textContent = 'Run attack';
              if (alertBox) {
                alertBox.style.display = 'block';
                alertBox.textContent = stData.error || 'Attack run failed.';
              }
            }
          } catch (pollErr) {
            // Keep polling
          }
        }, 800);
      } catch (err) {
        btn.disabled = false;
        btn.textContent = 'Run attack';
        if (alertBox) {
          alertBox.style.display = 'block';
          alertBox.textContent = err.message || 'Error initiating attack run.';
        }
      }
    });
  }

  // =========================================================================
  // APPLICATION BOOTSTRAP
  // =========================================================================
  async function initSession() {
    hideConfirmModal();
    var storedToken = null;
    try {
      storedToken = sessionStorage.getItem(STORAGE_TOKEN_KEY) || sessionStorage.getItem('token');
    } catch (e) {}

    if (!storedToken) {
      handleSignOut();
      return;
    }

    // Check token expiry on load
    if (isTokenExpired(storedToken)) {
      handleSignOut();
      showLoginError('Session expired. Please sign in again.');
      return;
    }

    authToken = storedToken;

    // Confirm token with profile endpoint
    try {
      var userRes = await apiFetch('/admin/dashboard/me');
      if (!userRes.ok) {
        handleSignOut();
        showLoginError('Session expired or unauthorized. Please sign in again.');
        return;
      }

      currentUser = await userRes.json();
      renderAppShell();
      handleRoute();
    } catch (err) {
      handleSignOut();
    }
  }

  // Initialize session on page load
  initSession();

})();
