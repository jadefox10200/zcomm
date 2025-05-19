document.addEventListener('DOMContentLoaded', () => {
    // State
    let currentZID = null;
    let currentUsername = null;
    let currentBasket = 'inbox';
    let currentConversation = null;
    let isArchivedView = false;

    // UI Elements
    const screens = {
        login: document.getElementById('login-screen'),
        zid: document.getElementById('zid-screen'),
        app: document.getElementById('app-screen')
    };
    const loginElements = {
        username: document.getElementById('login-username'),
        password: document.getElementById('login-password'),
        loginBtn: document.getElementById('login-btn'),
        createAccountBtn: document.getElementById('create-account-btn'),
        error: document.getElementById('login-error')
    };
    const zidElements = {
        select: document.getElementById('zid-select'),
        selectBtn: document.getElementById('select-zid-btn'),
        createBtn: document.getElementById('create-zid-btn'),
        logoutBtn: document.getElementById('logout-btn'),
        error: document.getElementById('zid-error')
    };
    const appElements = {
        onlineStatus: document.getElementById('online-status'),
        currentZID: document.getElementById('current-zid'),
        logoutBtn: document.getElementById('app-logout-btn'),
        basketTabs: document.getElementById('basket-tabs').children,
        basketCounts: {
            inbox: document.getElementById('inbox-count'),
            pending: document.getElementById('pending-count'),
            out: document.getElementById('out-count'),
            awaiting: document.getElementById('awaiting-count')
        },
        basketContent: document.getElementById('basket-content'),
        basketTitle: document.getElementById('basket-title'),
        dispatchList: document.getElementById('dispatch-list'),
        conversationContent: document.getElementById('conversation-content'),
        conversationTitle: document.getElementById('conversation-title'),
        conversationMessages: document.getElementById('conversation-messages'),
        archiveConvBtn: document.getElementById('archive-conv-btn'),
        activeConvsBtn: document.getElementById('active-convs-btn'),
        archivedConvsBtn: document.getElementById('archived-convs-btn'),
        conversationList: document.getElementById('conversation-list'),
        contactList: document.getElementById('contact-list'),
        contactAlias: document.getElementById('contact-alias'),
        contactZID: document.getElementById('contact-zid'),
        addContactBtn: document.getElementById('add-contact-btn'),
        dispatchRecipient: document.getElementById('dispatch-recipient'),
        dispatchSubject: document.getElementById('dispatch-subject'),
        dispatchBody: document.getElementById('dispatch-body'),
        dispatchConvID: document.getElementById('dispatch-conv-id'),
        sendDispatchBtn: document.getElementById('send-dispatch-btn'),
        sendEndDispatchBtn: document.getElementById('send-end-dispatch-btn')
    };

    // Show specific screen
    function showScreen(screen) {
        Object.values(screens).forEach(s => s.classList.add('hidden'));
        screens[screen].classList.remove('hidden');
    }

    // Display error message
    function showError(element, message) {
        element.textContent = message;
        element.classList.remove('hidden');
        setTimeout(() => element.classList.add('hidden'), 5000);
    }

    // Update online status
    async function updateOnlineStatus() {
        try {
            const isOnline = await window.go.main.App.IsOnline();
            appElements.onlineStatus.textContent = isOnline ? 'Online' : 'Offline';
            appElements.onlineStatus.classList.toggle('text-green-500', isOnline);
            appElements.onlineStatus.classList.toggle('text-red-500', !isOnline);
        } catch (err) {
            console.error('Failed to check online status:', err);
        }
    }

    // Update basket counts
    async function updateBasketCounts() {
        try {
            const counts = await window.go.main.App.GetBasketCounts();
            Object.keys(counts).forEach(basket => {
                appElements.basketCounts[basket].textContent = counts[basket];
            });
        } catch (err) {
            console.error('Failed to update basket counts:', err);
        }
    }

    // Render baskets
    async function renderBasket(basket) {
        currentBasket = basket;
        appElements.basketContent.classList.remove('hidden');
        appElements.conversationContent.classList.add('hidden');
        appElements.basketTitle.textContent = basket.charAt(0).toUpperCase() + basket.slice(1);
        appElements.dispatchList.innerHTML = '';
        Array.from(appElements.basketTabs).forEach(tab => {
            tab.classList.toggle('tab-active', tab.dataset.tab === basket);
            tab.classList.toggle('tab-inactive', tab.dataset.tab !== basket);
        });

        try {
            const dispatches = await window.go.main.App.GetBasketDispatches(basket);
            dispatches.forEach(disp => {
                const div = document.createElement('div');
                div.className = 'border p-4 rounded';
                div.innerHTML = `
                    <p><strong>From:</strong> ${disp.From}</p>
                    <p><strong>Subject:</strong> ${disp.Subject}</p>
                    <p><strong>Body:</strong> ${disp.Body}</p>
                    <p><strong>Timestamp:</strong> ${new Date(disp.Timestamp * 1000).toLocaleString()}</p>
                    <div class="flex space-x-2 mt-2">
                        ${basket !== 'out' ? `
                            <button class="action-btn bg-blue-500 text-white p-1 rounded hover:bg-blue-600" data-action="answer">Answer</button>
                            <button class="action-btn bg-green-500 text-white p-1 rounded hover:bg-green-600" data-action="ack">Ack</button>
                            <button class="action-btn bg-yellow-500 text-white p-1 rounded hover:bg-yellow-600" data-action="pending">Pending</button>
                            <button class="action-btn bg-red-500 text-white p-1 rounded hover:bg-red-600" data-action="decline">Decline</button>
                        ` : ''}
                        ${basket === 'out' ? `
                            <button class="action-btn bg-red-500 text-white p-1 rounded hover:bg-red-600" data-action="pullback">Pull Back</button>
                        ` : ''}
                    </div>
                `;
                div.querySelectorAll('.action-btn').forEach(btn => {
                    btn.addEventListener('click', () => handleDispatchAction(disp.DispatchID, btn.dataset.action));
                });
                appElements.dispatchList.appendChild(div);
            });
        } catch (err) {
            console.error('Failed to load dispatches:', err);
        }
    }

    // Handle dispatch actions
    async function handleDispatchAction(dispatchID, action) {
        try {
            let replyBody = '';
            if (action === 'answer') {
                replyBody = prompt('Enter reply body:') || '';
            }
            const isEnd = action === 'ack';
            await window.go.main.App.HandleDispatchAction(currentBasket, dispatchID, action, replyBody, isEnd);
            await renderBasket(currentBasket);
            await updateBasketCounts();
        } catch (err) {
            console.error(`Failed to handle action ${action}:`, err);
        }
    }

    // Render conversations
    async function renderConversations(archived) {
        isArchivedView = archived;
        appElements.conversationList.innerHTML = '';
        appElements.activeConvsBtn.classList.toggle('bg-blue-500', !archived);
        appElements.activeConvsBtn.classList.toggle('text-white', !archived);
        appElements.activeConvsBtn.classList.toggle('bg-gray-200', archived);
        appElements.archivedConvsBtn.classList.toggle('bg-blue-500', archived);
        appElements.archivedConvsBtn.classList.toggle('text-white', archived);
        appElements.archivedConvsBtn.classList.toggle('bg-gray-200', !archived);

        try {
            const conversations = await window.go.main.App.GetConversations(archived);
            conversations.forEach(conv => {
                const button = document.createElement('button');
                button.className = 'w-full p-2 bg-gray-200 rounded text-left hover:bg-gray-300';
                button.textContent = `${conv.Subject} (${conv.ConID})`;
                button.addEventListener('click', () => renderConversation(conv.ConID));
                appElements.conversationList.appendChild(button);
            });
        } catch (err) {
            console.error('Failed to load conversations:', err);
        }
    }

    // Render a single conversation
    async function renderConversation(conID) {
        currentConversation = conID;
        appElements.basketContent.classList.add('hidden');
        appElements.conversationContent.classList.remove('hidden');
        appElements.conversationTitle.textContent = `Conversation: ${conID}`;
        appElements.conversationMessages.innerHTML = '';

        try {
            const conv = await window.go.main.App.GetConversation(conID);
            appElements.conversationTitle.textContent = `Conversation: ${conv.Subject} (${conID})`;
            appElements.archiveConvBtn.textContent = conv.Ended ? 'Unarchive' : 'Archive';
            conv.Dispatches.forEach(disp => {
                const div = document.createElement('div');
                div.className = 'border p-4 rounded';
                div.innerHTML = `
                    <p><strong>From:</strong> ${disp.From}</p>
                    <p><strong>Subject:</strong> ${disp.Subject}</p>
                    <p><strong>Body:</strong> ${disp.Body}</p>
                    <p><strong>Timestamp:</strong> ${new Date(disp.Timestamp * 1000).toLocaleString()}</p>
                `;
                appElements.conversationMessages.appendChild(div);
            });
        } catch (err) {
            console.error('Failed to load conversation:', err);
        }
    }

    // Render contacts
    async function renderContacts() {
        appElements.contactList.innerHTML = '';
        try {
            const contacts = await window.go.main.App.ListContacts();
            contacts.forEach(contact => {
                const div = document.createElement('div');
                div.className = 'flex justify-between p-2 bg-gray-200 rounded';
                div.innerHTML = `
                    <span>${contact.Alias} (${contact.ZID})</span>
                    <button class="bg-red-500 text-white p-1 rounded hover:bg-red-600">Remove</button>
                `;
                div.querySelector('button').addEventListener('click', async () => {
                    try {
                        await window.go.main.App.RemoveContact(contact.Alias);
                        renderContacts();
                    } catch (err) {
                        console.error('Failed to remove contact:', err);
                    }
                });
                appElements.contactList.appendChild(div);
            });
        } catch (err) {
            console.error('Failed to load contacts:', err);
        }
    }

    // Login handler
    loginElements.loginBtn.addEventListener('click', async () => {
        const username = loginElements.username.value.trim();
        const password = loginElements.password.value;
        if (!username || !password) {
            showError(loginElements.error, 'Username and password are required');
            return;
        }
        try {
            const zids = await window.go.main.App.Login(username, password);
            currentUsername = username;
            zidElements.select.innerHTML = zids.map(zid => `<option value="${zid}">${zid}</option>`).join('');
            showScreen('zid');
        } catch (err) {
            showError(loginElements.error, 'Login failed: ' + err.message);
        }
    });

    // Create account handler
    loginElements.createAccountBtn.addEventListener('click', async () => {
        const username = loginElements.username.value.trim();
        const password = loginElements.password.value;
        if (!username || !password) {
            showError(loginElements.error, 'Username and password are required');
            return;
        }
        try {
            await window.go.main.App.CreateAccount(username, password);
            showError(loginElements.error, 'Account created successfully');
            loginElements.username.value = '';
            loginElements.password.value = '';
        } catch (err) {
            showError(loginElements.error, 'Create account failed: ' + err.message);
        }
    });

    // Select ZID handler
    zidElements.selectBtn.addEventListener('click', async () => {
        const zid = zidElements.select.value;
        if (!zid) {
            showError(zidElements.error, 'Please select a ZID');
            return;
        }
        try {
            await window.go.main.App.SelectZID(zid);
            currentZID = zid;
            appElements.currentZID.textContent = zid;
            showScreen('app');
            updateOnlineStatus();
            updateBasketCounts();
            renderBasket('inbox');
            renderConversations(false);
            renderContacts();
        } catch (err) {
            showError(zidElements.error, 'Failed to select ZID: ' + err.message);
        }
    });

    // Create ZID handler
    zidElements.createBtn.addEventListener('click', async () => {
        try {
            const zid = await window.go.main.App.CreateZID(currentUsername);
            zidElements.select.innerHTML += `<option value="${zid}">${zid}</option>`;
            zidElements.select.value = zid;
            showError(zidElements.error, 'ZID created successfully');
        } catch (err) {
            showError(zidElements.error, 'Failed to create ZID: ' + err.message);
        }
    });

    // Logout handlers
    zidElements.logoutBtn.addEventListener('click', async () => {
        try {
            await window.go.main.App.Logout();
            currentZID = null;
            currentUsername = null;
            showScreen('login');
        } catch (err) {
            showError(zidElements.error, 'Logout failed: ' + err.message);
        }
    });
    appElements.logoutBtn.addEventListener('click', async () => {
        try {
            await window.go.main.App.Logout();
            currentZID = null;
            currentUsername = null;
            showScreen('login');
        } catch (err) {
            console.error('Logout failed:', err);
        }
    });

    // Basket tab handlers
    Array.from(appElements.basketTabs).forEach(tab => {
        tab.addEventListener('click', () => renderBasket(tab.dataset.tab));
    });

    // Conversation view handlers
    appElements.activeConvsBtn.addEventListener('click', () => renderConversations(false));
    appElements.archivedConvsBtn.addEventListener('click', () => renderConversations(true));

    // Archive conversation handler
    appElements.archiveConvBtn.addEventListener('click', async () => {
        if (!currentConversation) return;
        try {
            const conv = await window.go.main.App.GetConversation(currentConversation);
            await window.go.main.App.ToggleConversationArchive(currentConversation, !conv.Ended);
            renderConversations(isArchivedView);
            appElements.conversationContent.classList.add('hidden');
            currentConversation = null;
        } catch (err) {
            console.error('Failed to toggle archive:', err);
        }
    });

    // Add contact handler
    appElements.addContactBtn.addEventListener('click', async () => {
        const alias = appElements.contactAlias.value.trim();
        const zid = appElements.contactZID.value.trim();
        if (!alias || !zid) {
            alert('Alias and ZID are required');
            return;
        }
        try {
            await window.go.main.App.AddContact(alias, zid);
            appElements.contactAlias.value = '';
            appElements.contactZID.value = '';
            renderContacts();
        } catch (err) {
            console.error('Failed to add contact:', err);
        }
    });

    // Send dispatch handler
    async function sendDispatch(isEnd) {
        const recipient = appElements.dispatchRecipient.value.trim();
        const subject = appElements.dispatchSubject.value.trim();
        const body = appElements.dispatchBody.value;
        const convID = appElements.dispatchConvID.value.trim();
        if (!recipient || !subject) {
            alert('Recipient and subject are required');
            return;
        }
        try {
            const resolvedRecipient = await window.go.main.App.ResolveAlias(recipient);
            await window.go.main.App.CreateAndSendDispatch(resolvedRecipient, subject, body, convID, isEnd);
            appElements.dispatchRecipient.value = '';
            appElements.dispatchSubject.value = '';
            appElements.dispatchBody.value = '';
            appElements.dispatchConvID.value = '';
            await updateBasketCounts();
            if (currentBasket === 'out') {
                await renderBasket('out');
            }
            if (currentConversation) {
                await renderConversation(currentConversation);
            }
        } catch (err) {
            console.error('Failed to send dispatch:', err);
        }
    }

    appElements.sendDispatchBtn.addEventListener('click', () => sendDispatch(false));
    appElements.sendEndDispatchBtn.addEventListener('click', () => sendDispatch(true));

    // Periodic updates
    setInterval(updateOnlineStatus, 5000);
    setInterval(updateBasketCounts, 10000);

    // Initial screen
    showScreen('login');
});