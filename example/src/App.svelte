<script>
	import LocalAuth from '../../src/SvelteLocalAuth.svelte'; //Import Svelte component
	import SillySecretEditor from './SillySecretEditor.svelte';
</script>

<main>
	<h1>Local store for secrets</h1>
	<!--Use component with custom local storage name-->
	<LocalAuth storageName='privateData'>
		<!--The inner components are shown after authentication-->
		<SillySecretEditor/>
	</LocalAuth>
</main>

<style>
    main {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }
</style>