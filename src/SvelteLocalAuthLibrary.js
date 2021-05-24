import { writable } from 'svelte/store';

export const secrets = writable(null); //Put and get your secrets here. They will be encripted and saved in state.
export const authenticated = writable(false);

export function logout () {
    authenticated.set(false);
    secrets.set(null)
}