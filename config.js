import {config} from 'dotenv'

config()

console.log(process.env.MONGODB_URI);