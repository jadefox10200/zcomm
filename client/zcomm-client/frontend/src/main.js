document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM fully loaded, initializing ZComm Messenger');

    // State
    let currentZID = null;
    let currentUsername = null;
    let currentBasket = null;
    let currentConversation = null;
    let currentDispatch = null;
    let isArchivedView = false;
    let currentTab = 'compose';

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
        sidebarTabs: document.getElementById('sidebar-tabs').children,
        basketCounts: {
            inbox: document.getElementById('inbox-count'),
            pending: document.getElementById('pending-count'),
            out: document.getElementById('out-count'),
            awaiting: document.getElementById('awaiting-count')
        },
        mainContent: document.getElementById('main-content'),
        composeContent: document.getElementById('compose-content'),
        basketContent: document.getElementById('basket-content'),
        basketTitle: document.getElementById('basket-title'),
        dispatchList: document.getElementById('dispatch-list'),
        dispatchContent: document.getElementById('dispatch-content'),
        dispatchActions: document.getElementById('dispatch-actions'),
        dispatchDetails: document.getElementById('dispatch-details'),
        replyContent: document.getElementById('reply-content'),
        replyRecipient: document.getElementById('reply-recipient'),
        replySubject: document.getElementById('reply-subject'),
        replyBody: document.getElementById('reply-body'),
        replyConvID: document.getElementById('reply-conv-id'),
        sendReplyBtn: document.getElementById('send-reply-btn'),
        cancelReplyBtn: document.getElementById('cancel-reply-btn'),
        conversationContent: document.getElementById('conversation-content'),
        conversationTitle: document.getElementById('conversation-title'),
        conversationMessages: document.getElementById('conversation-messages'),
        archiveConvBtn: document.getElementById('archive-conv-btn'),
        contactsContent: document.getElementById('contacts-content'),
        contactsList: document.getElementById('contacts-list'),
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

    // Debug: Verify UI elements
    console.log('Login button:', loginElements.loginBtn);
    console.log('Login error element:', loginElements.error);
    console.log('Reply button:', appElements.sendReplyBtn);

    // Show specific screen
    function showScreen(screen) {
        console.log(`Switching to screen: ${screen}`);
        Object.values(screens).forEach(s => s.classList.add('hidden'));
        screens[screen].classList.remove('hidden');
    }

    // Display error message
    function showError(element, message) {
        console.log(`Showing error: ${message}`);
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

    // Render content based on selected tab
    async function renderContent(tab) {
        currentTab = tab;
        currentDispatch = null;
        appElements.composeContent.classList.add('hidden');
        appElements.basketContent.classList.add('hidden');
        appElements.dispatchContent.classList.add('hidden');
        appElements.replyContent.classList.add('hidden');
        appElements.conversationContent.classList.add('hidden');
        appElements.contactsContent.classList.add('hidden');
        Array.from(appElements.sidebarTabs).forEach(t => {
            t.classList.toggle('tab-active', t.dataset.tab === tab);
            t.classList.toggle('tab-inactive', t.dataset.tab !== tab);
        });

        if (tab === 'compose') {
            appElements.composeContent.classList.remove('hidden');
        } else if (['inbox', 'pending', 'out', 'awaiting'].includes(tab)) {
            await renderBasket(tab);
        } else if (tab === 'contacts') {
            await renderContactsMain();
        }
    }

    // Render baskets
    async function renderBasket(basket) {
        currentBasket = basket;
        currentDispatch = null;
        appElements.basketContent.classList.remove('hidden');
        appElements.dispatchContent.classList.add('hidden');
        appElements.replyContent.classList.add('hidden');
        appElements.basketTitle.textContent = basket.charAt(0).toUpperCase() + basket.slice(1);
        appElements.dispatchList.innerHTML = '';

        try {
            const dispatches = await window.go.main.App.GetBasketDispatches(basket);
            console.log('Dispatches for basket', basket, dispatches);
            dispatches.forEach(disp => {
                console.log('Dispatch object:', disp);
                const div = document.createElement('div');
                div.className = 'dispatch-row border-b';
                div.innerHTML = `
                    <span class="w-1/3 truncate">${disp.from_zid || 'unknown'}</span>
                    <span class="w-1/3 truncate">${disp.subject || 'No Subject'}</span>
                    <span class="w-1/3 text-right">${disp.timestamp ? new Date(disp.timestamp * 1000).toLocaleString() : 'unknown'}</span>
                `;
                div.addEventListener('click', () => renderDispatch(disp.dispatch_id));
                appElements.dispatchList.appendChild(div);
            });
        } catch (err) {
            console.error('Failed to load dispatches:', err);
        }
    }

    // Render a single dispatch
    async function renderDispatch(dispatchID) {
        currentDispatch = dispatchID;
        appElements.composeContent.classList.add('hidden');
        appElements.basketContent.classList.add('hidden');
        appElements.replyContent.classList.add('hidden');
        appElements.conversationContent.classList.add('hidden');
        appElements.contactsContent.classList.add('hidden');
        appElements.dispatchContent.classList.remove('hidden');
        appElements.dispatchDetails.innerHTML = '';
        appElements.dispatchActions.innerHTML = '';

        try {
            const disp = await window.go.main.App.GetDispatch(dispatchID);
            console.log('Full dispatch:', disp);
            appElements.dispatchDetails.innerHTML = `
                <p><strong>From:</strong> ${disp.from_zid || 'unknown'}</p>
                <p><strong>To:</strong> ${disp.to_zid || 'unknown'}</p>
                <p><strong>Subject:</strong> ${disp.subject || 'No Subject'}</p>
                <p><strong>Body:</strong> ${disp.body || ''}</p>
                <p><strong>Timestamp:</strong> ${disp.timestamp ? new Date(disp.timestamp * 1000).toLocaleString() : 'unknown'}</p>
                <p><strong>Conversation ID:</strong> ${disp.conversation_id || 'none'}</p>
            `;
            // Action buttons
            if (currentBasket !== 'out') {
                appElements.dispatchActions.innerHTML = `
                    <button class="action-btn bg-blue-500 text-white p-2 rounded hover:bg-blue-600" data-action="answer">Answer</button>
                    <button class="action-btn bg-green-500 text-white p-2 rounded hover:bg-green-600" data-action="ack">Ack</button>
                    <button class="action-btn bg-yellow-500 text-white p-2 rounded hover:bg-yellow-600" data-action="pending">Pending</button>
                    <button class="action-btn bg-red-500 text-white p-2 rounded hover:bg-red-600" data-action="decline">Decline</button>
                `;
            } else {
                appElements.dispatchActions.innerHTML = `
                    <button class="action-btn bg-red-500 text-white p-2 rounded hover:bg-red-600" data-action="pullback">Pull Back</button>
                `;
            }
            appElements.dispatchActions.querySelectorAll('.action-btn').forEach(btn => {
                btn.addEventListener('click', () => handleDispatchAction(dispatchID, btn.dataset.action, disp));
            });
        } catch (err) {
            console.error('Failed to load dispatch:', err);
            appElements.dispatchDetails.innerHTML = '<p class="text-red-500">Failed to load dispatch</p>';
        }
    }

    // Handle dispatch actions
    async function handleDispatchAction(dispatchID, action, dispatch) {
        try {
            if (action === 'answer') {
                // Show reply form
                appElements.dispatchContent.classList.add('hidden');
                appElements.replyContent.classList.remove('hidden');
                // Pre-fill form
                appElements.replyRecipient.value = dispatch.from_zid || '';
                appElements.replyConvID.value = dispatch.conversation_id || '';
                appElements.replySubject.value = `Re: ${dispatch.subject || 'No Subject'}`;
                appElements.replyBody.value = '';
                // Focus on body
                appElements.replyBody.focus();
                // Set up send and cancel handlers
                const sendReply = async () => {
                    const replyBody = appElements.replyBody.value.trim();
                    if (!replyBody) {
                        alert('Reply body is required');
                        return;
                    }
                    try {
                        await window.go.main.App.HandleDispatchAction(currentBasket, dispatchID, action, replyBody, false);
                        appElements.replyContent.classList.add('hidden');
                        appElements.basketContent.classList.remove('hidden');
                        await renderBasket(currentBasket);
                        await updateBasketCounts();
                        currentDispatch = null;
                    } catch (err) {
                        console.error('Failed to send reply:', err);
                        alert('Failed to send reply: ' + err.message);
                    }
                };
                const cancelReply = () => {
                    appElements.replyContent.classList.add('hidden');
                    appElements.dispatchContent.classList.remove('hidden');
                };
                // Remove existing listeners to prevent duplicates
                const sendBtn = appElements.sendReplyBtn.cloneNode(true);
                const cancelBtn = appElements.cancelReplyBtn.cloneNode(true);
                appElements.sendReplyBtn.replaceWith(sendBtn);
                appElements.cancelReplyBtn.replaceWith(cancelBtn);
                sendBtn.addEventListener('click', sendReply);
                cancelBtn.addEventListener('click', cancelReply);
                // Add Enter key support for sending
                appElements.replyBody.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' && e.ctrlKey) {
                        sendReply();
                    }
                });
                return; // Wait for user to submit or cancel
            }
            // Other actions (ack, pending, decline, pullback)
            const isEnd = action === 'ack';
            await window.go.main.App.HandleDispatchAction(currentBasket, dispatchID, action, '', isEnd);
            await renderBasket(currentBasket);
            await updateBasketCounts();
            appElements.dispatchContent.classList.add('hidden');
            appElements.basketContent.classList.remove('hidden');
            currentDispatch = null;
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
        appElements.composeContent.classList.add('hidden');
        appElements.basketContent.classList.add('hidden');
        appElements.dispatchContent.classList.add('hidden');
        appElements.replyContent.classList.add('hidden');
        appElements.contactsContent.classList.add('hidden');
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
                    <p><strong>From:</strong> ${disp.from_zid || 'unknown'}</p>
                    <p><strong>Subject:</strong> ${disp.subject || 'No Subject'}</p>
                    <p><strong>Body:</strong> ${disp.body || ''}</p>
                    <p><strong>Timestamp:</strong> ${disp.timestamp ? new Date(disp.timestamp * 1000).toLocaleString() : 'unknown'}</p>
                `;
                appElements.conversationMessages.appendChild(div);
            });
        } catch (err) {
            console.error('Failed to load conversation:', err);
        }
    }

    // Render contacts (sidebar)
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
                        if (currentTab === 'contacts') {
                            renderContactsMain();
                        }
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

    // Render contacts (main content)
    async function renderContactsMain() {
        appElements.contactsContent.classList.remove('hidden');
        appElements.contactsList.innerHTML = '';
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
                        renderContactsMain();
                    } catch (err) {
                        console.error('Failed to remove contact:', err);
                    }
                });
                appElements.contactsList.appendChild(div);
            });
        } catch (err) {
            console.error('Failed to load contacts:', err);
        }
    }

    // Login handler
    loginElements.loginBtn.addEventListener('click', async () => {
        console.log('Login button clicked');
        if (!loginElements.username || !loginElements.password || !loginElements.error) {
            console.error('Login elements missing:', {
                username: loginElements.username,
                password: loginElements.password,
                error: loginElements.error
            });
            return;
        }
        const username = loginElements.username.value.trim();
        const password = loginElements.password.value;
        if (!username || !password) {
            showError(loginElements.error, 'Username and password are required');
            return;
        }
        try {
            console.log('Attempting login with username:', username);
            if (!window.go || !window.go.main || !window.go.main.App) {
                throw new Error('Wails bindings not initialized');
            }
            const zids = await window.go.main.App.Login(username, password);
            console.log('Login successful, ZIDs:', zids);
            currentUsername = username;
            if (!zidElements.select) {
                console.error('ZID select element missing');
                return;
            }
            zidElements.select.innerHTML = zids.map(zid => `<option value="${zid}">${zid}</option>`).join('');
            showScreen('zid');
        } catch (err) {
            console.error('Login failed:', err);
            showError(loginElements.error, 'Login failed: ' + err.message);
        }
    });

    // Create account handler
    loginElements.createAccountBtn.addEventListener('click', async () => {
        console.log('Create account button clicked');
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
            console.error('Create account failed:', err);
            showError(loginElements.error, 'Create account failed: ' + err.message);
        }
    });

    // Select ZID handler
    async function selectZID() {
        console.log('Select ZID button clicked');
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
            renderContent('compose');
            renderConversations(false);
            renderContacts();
        } catch (err) {
            console.error('Failed to select ZID:', err);
            showError(zidElements.error, 'Failed to select ZID: ' + err.message);
        }
    }

    zidElements.selectBtn.addEventListener('click', selectZID);
    zidElements.select.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            selectZID();
        }
    });

    // Create ZID handler
    zidElements.createBtn.addEventListener('click', async () => {
        console.log('Create ZID button clicked');
        try {
            const zid = await window.go.main.App.CreateZID(currentUsername);
            zidElements.select.innerHTML += `<option value="${zid}">${zid}</option>`;
            zidElements.select.value = zid;
            showError(zidElements.error, 'ZID created successfully');
        } catch (err) {
            console.error('Failed to create ZID:', err);
            showError(zidElements.error, 'Failed to create ZID: ' + err.message);
        }
    });

    // Logout handlers
    zidElements.logoutBtn.addEventListener('click', async () => {
        console.log('ZID screen logout button clicked');
        try {
            await window.go.main.App.Logout();
            currentZID = null;
            currentUsername = null;
            showScreen('login');
        } catch (err) {
            console.error('Logout failed:', err);
            showError(zidElements.error, 'Logout failed: ' + err.message);
        }
    });
    appElements.logoutBtn.addEventListener('click', async () => {
        console.log('App screen logout button clicked');
        try {
            await window.go.main.App.Logout();
            currentZID = null;
            currentUsername = null;
            showScreen('login');
        } catch (err) {
            console.error('Logout failed:', err);
        }
    });

    // Sidebar tab handlers
    Array.from(appElements.sidebarTabs).forEach(tab => {
        tab.addEventListener('click', () => {
            console.log(`Sidebar tab clicked: ${tab.dataset.tab}`);
            renderContent(tab.dataset.tab);
        });
    });

    // Conversation view handlers
    appElements.activeConvsBtn.addEventListener('click', () => {
        console.log('Active conversations button clicked');
        renderConversations(false);
    });
    appElements.archivedConvsBtn.addEventListener('click', () => {
        console.log('Archived conversations button clicked');
        renderConversations(true);
    });

    // Archive conversation handler
    appElements.archiveConvBtn.addEventListener('click', async () => {
        console.log('Archive/Unarchive button clicked');
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
        console.log('Add contact button clicked');
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
            if (currentTab === 'contacts') {
                renderContactsMain();
            }
        } catch (err) {
            console.error('Failed to add contact:', err);
        }
    });

    // Send dispatch handler
    async function sendDispatch(isEnd) {
        console.log('Send dispatch button clicked, isEnd:', isEnd);
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