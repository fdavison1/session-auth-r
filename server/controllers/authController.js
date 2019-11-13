const bcrypt = require('bcrypt')
saltRounds = 10

module.exports ={
    async register(req, res){
        const db = req.app.get('db')
        const {email, password, isAdmin} = req.body
        let newUser = await db.get_user_username(email)
        newUser = newUser[0]
        if (newUser) return res.status(401).send('email already in use. try logging in.')
        const salt = bcrypt.genSaltSync(saltRounds)
        const hash = bcrypt.hashSync(password, salt)
        newUser = await db.register([email, hash, isAdmin])
        req.session.user = {
            id: newUser[0].id,
            isAdmin: isAdmin
        }
        res.status(200).send(req.session.user)
    },
    async login(req, res){
        const db = req.app.get('db')
        const {email, password} = req.body
        const sessionUser = await db.get_user_username(email)
        if(!sessionUser[0]){
            return res.status(404).send('this user does not exist')
        }
        const passwordCheck = bcrypt.compareSync(password, sessionUser[0].password)
        if(!passwordCheck){
            return res.status(404).send('wrong password')
        }
        req.session.user = {
            id: sessionUser[0].id,
            isAdmin: sessionUser[0].isadmin
        }
        res.status(200).send(req.session.user)
    },

    async logout(req, res){
        req.session.destroy()
        res.sendStatus(200)
}
}