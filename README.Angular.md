# Quick Guide to Angular Development

This guide provides a quick overview of the main commands, principles, and tips for developing applications with Angular.

---

## **1. Core Principles**

### **Components**
- Angular apps are built using **components**.
- Each component consists of:
  - **Template** (HTML): Defines the view.
  - **Class** (TypeScript): Handles logic and data.
  - **Metadata** (Decorators): Defines behavior (e.g., `@Component`).

### **Modules**
- Angular apps are modular and organized into **NgModules**.
- The root module is `AppModule` (`app.module.ts`).
- Use `@NgModule` to declare components, directives, pipes, and services.

### **Data Binding**
- **Interpolation**: `{{ data }}` (Display data in the template).
- **Property Binding**: `[property]="data"` (Bind data to an element property).
- **Event Binding**: `(event)="handler()"` (Bind events to methods).
- **Two-Way Binding**: `[(ngModel)]="data"` (Sync data between the template and class).

### **Directives**
- **Structural Directives**: Modify the DOM (e.g., `*ngIf`, `*ngFor`).
- **Attribute Directives**: Change the appearance or behavior of elements (e.g., `ngClass`, `ngStyle`).

### **Services**
- Use services (`@Injectable`) to share data and logic across components.
- Services are typically injected into components via **Dependency Injection (DI)**.

### **Routing**
- Use the `RouterModule` to define navigation paths and load components dynamically.

---

## **2. Main Commands**

### **Angular CLI**
- Install Angular CLI globally: npx for a temporal ex
  ```bash
  npm install -g @angular/cli
  npx @angular/cli
  ```
- Create a new project:
  ```bash
  ng new project-name
  ```
- Serve the application:
  ```bash
  ng serve
  ```
- Generate components, services, modules, etc.:
  ```bash
  ng generate component component-name
  ng generate service service-name
  ng generate module module-name
  ```
- Build the project for production:
  ```bash
  ng build --prod
  ```
- Run unit tests:
  ```bash
  ng test
  ```
- Run end-to-end tests:
  ```bash
  ng e2e
  ```

---

## **3. Tips for Development**

### **Organize Your Code**
- Follow the **Feature Module** pattern: Group related components, directives, and pipes into modules.
- Use **Lazy Loading** for feature modules to improve performance.

### **Use Reactive Forms**
- For complex forms, use **Reactive Forms** (`FormGroup`, `FormControl`) instead of template-driven forms.

### **State Management**
- For large applications, consider using state management libraries like **NgRx** or **Akita**.

### **Optimize Performance**
- Use `OnPush` change detection strategy for components to reduce unnecessary checks.
- Avoid heavy computations in templates; use **pipes** or **methods** in the component class.

### **Testing**
- Write unit tests for components, services, and pipes using **Jasmine** and **Karma**.
- Use **Protractor** for end-to-end testing.

### **Debugging**
- Use Angular's **Augury** Chrome extension for debugging and profiling.
- Enable **source maps** in `tsconfig.json` for better debugging experience.

### **Stay Updated**
- Angular releases updates regularly. Use `ng update` to keep your project up-to-date.

---

## **4. Common Pitfalls**

- **Memory Leaks**: Unsubscribe from observables to avoid memory leaks (use `takeUntil` or `async` pipe).
- **Change Detection**: Avoid triggering change detection too frequently (e.g., by using `ngZone.runOutsideAngular` for non-UI tasks).
- **Circular Dependencies**: Be cautious with circular imports between modules or services.

---

## **5. Useful Resources**

- [Angular Documentation](https://angular.io/docs)
- [Angular CLI GitHub](https://github.com/angular/angular-cli)
- [RxJS Documentation](https://rxjs.dev/) (for working with observables)
- [Angular University Blog](https://blog.angular-university.io/)

---

This guide covers the essentials to get started with Angular development. Happy coding! 🚀