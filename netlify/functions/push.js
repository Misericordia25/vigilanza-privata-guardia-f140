/* Carlo Doga: invio dei promemoria push, avvisi di turno e chiusura automatica dei check-out. Funzione pianificata ogni 15 minuti (prima ogni minuto: consumava crediti); esce subito se non c'è nulla in scadenza */
import { cron } from './sync.js';
export default async (req, ctx) => { await cron(ctx) };
export const config = { schedule: '*/15 * * * *' };
