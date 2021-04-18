const mongoose = require('mongoose')
const bcrypt = require('bcrypt')


const PostSchema = new mongoose.Schema({
    authorId: {
        type: String,
        required: [true],
        trim: true,
        lowercase: true
    },
    text: {
        type: String,
        trim: true,
        required: [true, 'Please enter text'],
    }
})


module.exports = mongoose.model('Post', PostSchema)