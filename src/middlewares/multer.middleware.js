import multer from "multer"

const storage = multer.diskStorage({
    //  File kaha par rakhni h 
    destination: function (req, file, cb){
        cb(null, "./public/temp")
    },
    //  Filename kya hoga
    filename: function(req, file, cb){
        cb(null, file.originalname)
    }
})

export const upload = multer({
    storage,
})