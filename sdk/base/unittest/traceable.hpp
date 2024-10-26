/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_UNITTEST_TRACEABLE__
#define __HOTPLACE_SDK_BASE_UNITTEST_TRACEABLE__

#include <sdk/base/system/trace.hpp>
#include <sdk/net/types.hpp>

namespace hotplace {

/**
 * @brief   traceable
 * @remarks
 *          // sketch
 *          class object : public traceable {
 *             public:
 *              object() {}
 *              void test() {
 *                  if (istraceable()) {
 *                      basic_stream bs;
 *                      bs << "what happens here ...";
 *                      traceevent(category_http_request, 0, &bs);
 *                  }
 *              }
 *          };
 *
 *          void runtest() {
 *              object o;
 *              auto lambda = [](trace_category_t category, uint32 event, stream_t* s) -> void {};
 *              o.settrace(lambda);
 *              o.test(); // run lambda inside
 *          }
 */
class traceable {
   public:
    traceable();
    traceable(const traceable& rhs);

    /**
     * @brief   istraceable
     * @return  true/false
     */
    bool istraceable();
    /**
     * @brief   settrace
     * @param   std::function<void(trace_category_t category, uint32 event, stream_t* s)> f [in]
     */
    virtual void settrace(std::function<void(trace_category_t category, uint32 event, stream_t* s)> f);
    /**
     * @brief   settrace
     * @param   traceable* diag [in]
     */
    virtual void settrace(traceable* diag);
    /**
     * @brief   event
     * @param   trace_category_t category [in]
     * @param   uint32 event [in]
     * @param   stream_t* [in]
     */
    void traceevent(trace_category_t category, uint32 event, stream_t*);
    void traceevent(trace_category_t category, uint32 event, const char* fmt, ...);

    /**
     * @brief   add
     * @sample
     *          class A : public traceable {
     *             public:
     *          };
     *          class B : public traceable {
     *             public:
     *              B() { addchain(&a); }
     *              A a;
     *          };
     *          void test() {
     *              b.settrace(trace_handler); // call B::settrace, A::settrace
     *          }
     */
    void addchain(traceable* tr);

   protected:
    std::function<void(trace_category_t, uint32, stream_t*)> _df;
    std::list<traceable*> children;
};

}  // namespace hotplace

#endif
