/* Vigilanza Privata: invio dei promemoria push. Funzione pianificata: gira ogni minuto ed esce subito se non c'è nulla in scadenza */
import { runPush } from './sync.js';
export default async () => { await runPush() };
export const config = { schedule: '* * * * *' };
