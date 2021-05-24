<script>
    import { secrets, logout } from '../../src/SvelteLocalAuthLibrary'; //Import secrets store and sugar functions
</script>

<main>
    <textarea bind:value={$secrets}></textarea> <!--Every time $secret are modified, it's encrypted ans saved to browser's local storage-->
    <button on:click="{logout}">Logout</button> <!--If logout, your component disapears, secret are cleared and a login is showed-->
    <!--You can store strings, numbers, arrays, objects any kind of data JSON interface can handle-->
</main>

<style>
    main {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
    }
</style>