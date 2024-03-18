import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from '../utils/ApiError.js'
import {User} from '../models/user.model.js'
import {uploadOnCloudinary} from '../utils/cloudinary.js'
import {ApiResponse} from '../utils/ApiResponse.js'
import  Jwt  from "jsonwebtoken"



//  Generate Acccess and Refresh token
const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
       await user.save({validateBeforeSave: false})

       return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh tokens")
    }
}


//  Register User 
const registerUser = asyncHandler( async (req, res) => {
    
    
    // 1.  get user details from frontend
    const {fullName, email, username, password} = req.body
    
    
    //  validation -- not empty
    if (fullName === "") {
        throw new ApiError(400, "fullname is required")
    }
    if([fullName, email, username, password].some((field) => field?.trim() === "" )) {
        throw new ApiError(400, "All field are required") 
        
    } 
    
    
    // 2.  check if user already exists
    const existedUser = await User.findOne({
        $or: [{email}, {username}]
    })
    if(existedUser){
        throw new ApiError(409, "User already exists")
    }
    
    
    // 3. check for images, check for avatar
    const avatarLocalPath = req.files?.avatar[0]?.path
    // const coverImageLocalPath = req.files?.coverImage[0]?.path
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.lenght > 0) {
            coverImageLocalPath = req.files?.coverImage[0]?.path
    }
        
    
    
    if (!avatarLocalPath) {
        throw new ApiError(400, "Missing avatar")
    }
    
    
    
    // 4. upload them to cloudinary, avatar
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    
    if (!avatar) {
        throw new ApiError(400, "Avatar is required")
    }
    
    
    // 5. create user object-- create entry in db 
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        username,
        password: username.toLowerCase(),
    })
    
    
    
    // 6. remove password and refresh token field from response 
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
        )
        
        
    // 7. check for user creation 
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering user")
    }
    

    // 8. return response 
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User created successfully")
    )
})


//  Login User
const loginUser = asyncHandler( async (req, res) => {
    // 1. req body -- data
    const {email, username, password} = req.body
    
    
    
    // 2. username, email -- check access
    if (!username && !email) {
        throw new ApiError(400, "username or email is required")
    }
    
    
    
    // 3. find the user
    const user = await User.findOne({
        $or: [{username}, {email}]
    })
    if (!user) {
        throw new ApiError(404, "User not found")
    }
    
    
    // 4. password check
    const isPasswordValid = await user.isPasswordCorrect(password)
    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid password")
    }
    
    
    
    // 5. access and refresh token 
    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)
    
    
    
    // 6. send cookie
    const loggedInUser = User.findById(User._id).select("-password -refresh-token")
    const options = {
        httpOnly : true,
        secure: true
    }
    
    
    
    // 7. Send response
    return res
    .status(200)
    .cookie("accesstoken", accessToken, options)
    .cookie("refreshtoken", refreshToken, options)
    .json(new ApiResponse(200, {
        user: loggedInUser, accessToken, refreshToken
    }, "User Logged in successfully"
    ))
})


// Logout User
const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
        req.body_id,
        {
            $set:{
                refreshToken: undefined
            },
            new: true
        }
    ) 
    const options = {
        httpOnly : true,
        secure: true
    }
    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User Logged out"))
})


//  Refresh access token
const refreshAccessToken = asyncHandler( async(req, res)=> {
 // request token
    const incommingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
    if (!incommingRefreshToken) {
        throw new ApiError(401, "Unauthorized request")
    }

try {
    //  Verify token
       const decodedToken =  Jwt.verify(
            incommingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET,
        )
    
    //  Find uaer
        const user = User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
    //  Match token
        if (incommingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
        }
    
    //  Generate refresh token
        const options = {
            httpOnly : true,
            secure: true
        }
      const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
    
    
    // Send Responce
        return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json( new ApiResponse(
        200,
        {
            accessToken, refreshToken: newRefreshToken
        }, "Access token refreshed"
      ))
} catch (error) {
    throw new ApiError(401, error?.message, "Invalid refresh token")
}
  
})


//  Change current Password
const changeCurrentPassword = asyncHandler( async(req, res)=> {
    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)
   const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

   if (!isPasswordCorrect) {
    throw new ApiError(400,"Invalid old password")
   }

   user.password = newPassword
   await user.save({validateBeforeSave: false})

   return res.status(200)
   .json( new ApiResponse(200, {}, "Password change successfully"))
})

// Get current User 
const getCurrentUser = asyncHandler( async(req, res)=> {
    return res
           .status(200)
           .json( new ApiResponse(200, req.user, "Current user fetched"))
})

//  Update Account details
const updateAccountDetails = asyncHandler( async(req, res)=> {
//  Get information from body 
    const {fullName, email} = req.body

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }

// Find user
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                fullName,
                email
            }
        },
        {new: true}
        
    ).select("-password")

    return res.status(200)
    .json(new ApiResponse(200, user, " Account details Updated successfully"))
})

//  Avatar Update
const updateUserAvatar = asyncHandler(async(req, res)=> {
//  Get file
    const avatarLocalPath = req.file?.path
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

// Upload to cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    if (!avatar) {
        throw new ApiError(400, "Error uploading avatar to cloudinary")
    }

// Update avatar
   const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set: {
                avatar: avatar.url
            }
        },
        {new: true}
        ).select("-password")


//  Send Response
return res.status(200)
.json(new ApiResponse(200, user, " Avatar Updated successfully"))
})


//  Update cover image
const updateUserCoverImage = asyncHandler(async(req, res)=> {
//  Get file
    const coverImageLocalPath = req.file?.path
    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover Image file is missing")
    }

// Upload to cloudinary
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if (!avatar) {
        throw new ApiError(400, "Error uploading cover Image to cloudinary")
    }

// Update cover image
   const user = await User.findByIdAndUpdate(req.user?._id,
        {
            $set: {
                coverImage: coverImage.url
            }
        },
        {new: true}
        ).select("-password")
        
        
// send respose
        return res.status(200)
     .json(new ApiResponse(200, user, " Cover Image Updated successfully"))
})

export 
{
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
}