const path = require('path');
const Product = require('../models/product-schema');
const User = require('../models/user-schema');
const fs = require('fs');

class ProductController {
    static async createProduct(req, res) {
        try {
            const { nameProduct, price, description, category, releaseDate, latitude, longitude } = req.body;
            const sellerID = req.user.id;
            console.log(sellerID);
            const findSellerID = await User.findById(sellerID);
            if (!findSellerID) {
                const error = new Error('Seller ID not found');
                error.statusCode = 401;
                throw error;
            }
            const product = new Product({
                nameProduct,
                price,
                description,
                category,
                sellerID,
                releaseDate,
                latitude,
                longitude
            });
            product.image = req.file.filename;
            console.log(product);
            await product.save();

            res.status(201).json({
                message: 'Product added',
                data: product
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async getAllProduct(req, res) {
        try {
            // Check if there's a query parameter for search
            const { search } = req.query;
            let products;
            if (search) {
                // If search query parameter exists, perform search by search
                products = await Product.find({ nameProduct: { $regex: new RegExp(search, 'i') } }).populate('sellerID');
            } else {
                // Otherwise, get all products
                products = await Product.find().populate('sellerID');
            }
            console.log(products);
            res.status(200).json({
                message: 'Get products',
                data: products
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }


    //TODO without search
    // static async getAllProduct(req, res) {
    //     try {
    //         const products = await Product.find().populate('sellerID');
    //         console.log(products);
    //         res.status(200).json({
    //             message: 'Get all products',
    //             data: products
    //         });
    //     } catch (error) {
    //         res.status(500).json({
    //             error: true,
    //             message: error.message
    //         });
    //     }
    // }

    static async getAdminProduct(req, res) {
        try {
            const sellerID = req.user.id;
            const products = await Product.find({ sellerID: sellerID })
                .populate('sellerID');
            console.log(products);
            res.status(200).json({
                message: 'Get all products',
                data: products
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async getProductById(req, res) {
        try {
            const { id } = req.params;
            const product = await Product.findById(id).populate('sellerID');
            res.status(200).json({
                message: 'Get product by id',
                data: product
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async updateProduct(req, res) {
        try {
            const { id } = req.params;
            const { nameProduct, price, description, category, releaseDate, latitude, longitude } = req.body;

            const findProduct = await Product.findById(id);
            const filePath = path.join(__dirname, `../uploads/${findProduct.image}`);
            // Check if the image file exists
            if (fs.existsSync(filePath)) {
                // Delete the image file
                fs.unlinkSync(filePath);
            } else {
                console.log("File not found:", filePath);
            }

            let newImage;
            if (req.file) {
                newImage = req.file.filename;
            } else {
                newImage = findProduct.image; // Keep the existing image if no new file uploaded
            }

            const sellerID = req.user.id;
            const product = await Product.findByIdAndUpdate(id, {
                nameProduct,
                price,
                description,
                image: newImage,
                category,
                sellerID,
                releaseDate,
                latitude,
                longitude
            });
            res.status(200).json({
                message: 'Update product success',
                data: product
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async deleteProduct(req, res) {
        try {
            const { id } = req.params;
            const product = await Product.findByIdAndDelete(id);
            const image = product.image;
            const pathh = path.join(__dirname, `../uploads/${image}`);
            console.log(pathh);
            fs.unlinkSync(pathh);
            res.status(200).json({
                message: 'Delete product success',
                data: product
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

    static async getProductsByshopName(req, res) {
        try {
            const { shopName } = req.params; // Mengasumsikan shopName dikirim sebagai parameter URL
            const shop = await User.findOne({ shopName });
            if (!shop) {
                return res.status(404).json({
                    message: 'No found Shop for this shop',
                });
            }
            const products = await Product.find({ sellerID: shop._id }).populate('sellerID');
            if (products.length === 0) {
                return res.status(404).json({
                    message: 'No products found for this shop',
                });
            }
            res.status(200).json({
                message: 'Get products by shop name',
                data: products
            });
        } catch (error) {
            res.status(500).json({
                error: true,
                message: error.message
            });
        }
    }

}

module.exports = ProductController;