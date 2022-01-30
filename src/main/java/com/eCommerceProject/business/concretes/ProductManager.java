package com.eCommerceProject.business.concretes;

import com.eCommerceProject.business.abstracts.ProductService;;
import com.eCommerceProject.dataAccess.abstracts.ProductDao;
import com.eCommerceProject.entities.concretes.Product;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProductManager implements ProductService {

    private final ProductDao productDao;

    @Override
    public List<Product> getAll() {
        return this.productDao.findAll();
    }

    @Override
    public void add(Product product) {
        this.productDao.save(product);
    }

    @Override
    public List<Product> getByproductName(String productName) {
        return this.productDao.getByproductName(productName);
    }

    @Override
    public List<Product> getByproductBrand(String productBrand) {
       return this.productDao.getByproductBrand(productBrand);
    }

    @Override
    public void deleteById(int id) {
        this.productDao.deleteById(id);
    }

    @Override
    public List<Product> slice(Pageable pageable) {
        final List<Product> products = this.productDao.findAll(pageable).stream().collect(Collectors.toList());
        return products;
    }

}
