<script>

	import { writable } from 'svelte/store';

	import { authenticated, secrets } from './SvelteLocalAuthLibrary'

    export let storageName = 'SvelteLocalAuth';

	//export let secrets = writable(null); //Put and get your secrets here. They will be encripted and saved in state.

	const state = writable(
		JSON.parse(
			localStorage.getItem(storageName)
		) || {}
	);

	//const authenticated = writable(false);

	let newPassphrase, newPassphraseVerification, newPassphraseVerificationInput, validPassphrase, passphrase, passphraseInput, key;

	async function keySeed (passphrase) {
		let enc = new TextEncoder();
		let encoded = enc.encode(passphrase);
		let seed = await window.crypto.subtle.importKey(
			"raw",
			encoded,
			{name: "PBKDF2"},
			false,
			["deriveBits", "deriveKey"]
 		);
		return seed;
	}

	async function derivateKey (passphrase, salt) {
		let key = await window.crypto.subtle.deriveKey(
			{
			"name": "PBKDF2",
			salt: base64Tobuffer(salt),
			"iterations": 100000,
			"hash": "SHA-512"
			},
			await keySeed(passphrase),
			{ "name": "AES-CTR", "length": 256},
			true,
			[ "encrypt", "decrypt" ]
		);
		return key;
	}

	function bufferToBase64 (buffer) {
		let binaryString = '';
		const bytesArray = new Uint8Array(buffer);
		const len = bytesArray.byteLength;
		for (let i = 0; i < len; i++) {
			binaryString += String.fromCharCode(bytesArray[i]);
		}
		const base64 = btoa(binaryString);
		return base64;
	}

	function base64Tobuffer(base64) {
		const binaryString = atob(base64);
		const len = binaryString.length;
		const bytesArray = new Uint8Array(len);
		for (let i = 0; i < len; i++) {
			bytesArray[i] = binaryString.charCodeAt(i);
		}
		return bytesArray.buffer;
	}

	async function encrypt (string,key) {
		const encoder = new TextEncoder();
		const encoded = encoder.encode(string);
		const counterBuffer = crypto.getRandomValues(new Uint8Array(16));
		const counter = bufferToBase64(counterBuffer);
		try {
			const encryptedBuffer = await window.crypto.subtle.encrypt(
				{
					name: "AES-CTR",
					counter: counterBuffer,
					length: 64
				},
				key,
				encoded,
			);
			const encrypted = bufferToBase64(encryptedBuffer);
			return { encrypted, counter };
		} catch (err) {
			console.error(err);
		}
	}

	async function decrypt (encrypted,key,counter) {
		const counterBuffer = base64Tobuffer(counter);
		const encryptedBuffer = base64Tobuffer(encrypted);
		try {
			const decrypted = await window.crypto.subtle.decrypt(
				{
					name: "AES-CTR",
					counter: counterBuffer,
					length: 64
				},
				key,
				encryptedBuffer,
			);
			const dec = new TextDecoder();
			const secret = dec.decode(decrypted);
			return secret;
		} catch (err) {
			console.error(err);
		}
	}

	function download (jsonFilecontent) {
		const blob = new Blob([jsonFilecontent], { type: 'application/json' });

		const a = document.createElement('a');

		a.style.display = "none";
		a.download = 'backup.json';
		a.href = URL.createObjectURL(blob);
		a.dataset.downloadurl = ['application/json', a.download, a.href].join(':');

		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		setTimeout(function() { URL.revokeObjectURL(a.href); }, 1500);
	}

	async function loginHandler (ev) {
		ev.preventDefault();
		if (validPassphrase) {
			key = await derivateKey(passphrase,$state.salt);
			$authenticated = true;
		}
	}

	async function sha256 (str) {
		const enc = new TextEncoder();
		const passphraseBuffer = enc.encode(str);
		const hashBuffer = await crypto.subtle.digest('sha-256',passphraseBuffer);
		const hash = bufferToBase64(hashBuffer);
		return hash;
	}

	function validateNewPassphrase () {
		validPassphrase = newPassphrase === newPassphraseVerification;
		newPassphraseVerificationInput.setCustomValidity(validPassphrase ? '' : 'Las contraseñas no coinciden.');
	}

	async function validatePassphrase () {
		const hash = await sha256(passphrase);
		validPassphrase = hash === $state.identity;
		passphraseInput.setCustomValidity(validPassphrase ? '' : 'Contraseña invalida');
	}

	async function createPassphraseHandler (ev) {
		ev.preventDefault();
		if (validPassphrase) {
			const salt = bufferToBase64(crypto.getRandomValues(new Uint8Array(16)));
			const hash = await sha256(newPassphrase);
			key = await derivateKey(newPassphrase, salt);
			$authenticated = true;
			$state = {...$state, identity: hash, salt};
		}
	}

	async function loadSecrets () {
		if ($state.encrypted && $state.counter && $state.salt && key) {
			const dec = await decrypt($state.encrypted,key,$state.counter)
			$secrets = JSON.parse(dec);
		}
	}

	async function saveSecrets () {
		if (key) {
			const secret = JSON.stringify($secrets);
			const { encrypted, counter } = await encrypt(secret,key);
			$state = {...$state, encrypted, counter };
		}
	}

	state.subscribe(
        state => {
			let stateString = JSON.stringify(state);
			localStorage.setItem(storageName,stateString);
		}
    );

	$: if (key) loadSecrets();
	
	$: if ($secrets) saveSecrets();

</script>

<main>
    
    {#if $authenticated}
	<slot>
		<p>This is a place holder. Give me a content.</p>
		<p>This component provides a encrypted local storage and authentication for local web app.</p>
		<p>It will be usefull for PWA.</p>
		<p>Only shows children content (this slot) if user/password authentication is provided.</p>
		<p>Click the button for seting a testing secret in the local storage.</p>
		<button on:click="{()=>$secrets = {mySecretCardNumber: '0000 1111 2222 3333', mySecretCV: '123', creationTime: Date.now()}}">Set a secret</button>
		<p>The local storage: {JSON.stringify($state)}</p>
		<p>Your secrets: {JSON.stringify($secrets)}</p>
		<p>You can close de app start again and see your secrets are locally safe</p>
	</slot>
    {:else if $state.identity}
	<p>Authentication</p>
	<form on:submit="{loginHandler}">
		<input type="password" placeholder="Your password" bind:value="{passphrase}" on:input="{validatePassphrase}" bind:this={passphraseInput}/>
		<input type="submit"/>
	</form>
	{:else}
	<p>Passphrase creation form</p>
	<form on:submit="{createPassphraseHandler}">
		<input type="password" placeholder="Tu contraseña" bind:value="{newPassphrase}" on:input="{validateNewPassphrase}"/>
		<input type="password" placeholder="Repite tu contraseña" bind:value={newPassphraseVerification} on:input="{validateNewPassphrase}" bind:this={newPassphraseVerificationInput} />
		<input type="submit" value="Guardar"/>
	</form>
    {/if}

</main>