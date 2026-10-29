// teste com valor controlado pelo proprio teste
const status = async (id) => (await linhas(`SELECT status FROM eventos WHERE id = ${id}`))[0].status;
